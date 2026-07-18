package inspace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/thanet-s/inspace-cloud-kube-modules/modules/csi-driver/pkg/cloud"
)

const (
	maxMissingNodeAuthorityItems         = 4096
	missingNodeClaimAuthorityPageSize    = 4
	missingNodeAuthorityNodePageSize     = 32
	maxMissingNodeClaimAuthorityPages    = 1025
	maxMissingNodeAuthorityNodePages     = 129
	maxMissingNodeAuthorityResponseBytes = 8 << 20
	maxMissingNodeContinueTokenBytes     = 16 << 10
	karpenterNodeClaimAPIVersion         = "karpenter.sh/v1"
	karpenterNodeClaimKind               = "NodeClaim"
	karpenterNodeClaimListKind           = "NodeClaimList"
	karpenterTerminationFinalizer        = "karpenter.sh/termination"
	inspaceCreateProtectionFinalizer     = "karpenter.inspace.cloud/create-protection"
	inspaceNodeNameAnnotation            = "karpenter.inspace.cloud/node-name"
	inspaceCreateFenceAnnotation         = "karpenter.inspace.cloud/create-fence"
	inspaceOwnershipV3                   = "karpenter.inspace.cloud/v3"
	inspaceCreateFenceV3                 = "karpenter.inspace.cloud/create-fence-v3"
	inspaceCreateFenceMaterialized       = "materialized"
	inspaceFirewallAssignmentObserved    = "observed"
	karpenterRegisteredCondition         = "Registered"
	karpenterTerminatingCondition        = "InstanceTerminating"
	maxMissingNodeDescriptionBytes       = 64 << 10
	maxMissingNodeCreateFenceBytes       = 256 << 10
)

var (
	missingNodeDNSLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
	missingNodeLocationPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
	missingNodeHex32Pattern    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	missingNodeHex64Pattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// missingNodeDetachRequest contains only canonical cloud identity that the
// adapter has already established through exact InSpace reads. Kubernetes
// authority is independent: it must bind the absent Node name to this exact VM
// before a stale VolumeAttachment is allowed to finish ControllerUnpublish.
type missingNodeDetachRequest struct {
	NodeName         string
	Location         string
	VMUUID           string
	VMName           string
	VMHostname       string
	VMDescription    string
	DiskUUID         string
	NetworkUUID      string
	BillingAccountID int64
}

type missingNodeDetachAuthorizer interface {
	AuthorizeMissingNodeDetach(context.Context, missingNodeDetachRequest) error
}

type missingNodeObjectMeta struct {
	Name              string            `json:"name"`
	UID               string            `json:"uid"`
	ResourceVersion   string            `json:"resourceVersion"`
	DeletionTimestamp string            `json:"deletionTimestamp,omitempty"`
	Finalizers        []string          `json:"finalizers,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
}

type missingNodeCondition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

type missingNodeClaim struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Metadata   missingNodeObjectMeta  `json:"metadata"`
	Status     missingNodeClaimStatus `json:"status"`
}

type missingNodeClaimStatus struct {
	NodeName   string                 `json:"nodeName"`
	ProviderID string                 `json:"providerID"`
	Conditions []missingNodeCondition `json:"conditions"`
}

type missingNodeListMeta struct {
	ResourceVersion string `json:"resourceVersion"`
	Continue        string `json:"continue,omitempty"`
}

type missingNodeClaimList struct {
	APIVersion string              `json:"apiVersion"`
	Kind       string              `json:"kind"`
	Metadata   missingNodeListMeta `json:"metadata"`
	Items      []missingNodeClaim  `json:"items"`
}

type missingNodeKubernetesNode struct {
	Metadata struct {
		Name string `json:"name"`
		UID  string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		ProviderID string `json:"providerID"`
	} `json:"spec"`
}

type missingNodeKubernetesNodeList struct {
	APIVersion string                      `json:"apiVersion"`
	Kind       string                      `json:"kind"`
	Metadata   missingNodeListMeta         `json:"metadata"`
	Items      []missingNodeKubernetesNode `json:"items"`
}

type missingNodeOwnershipRecord struct {
	Schema                       string `json:"schema"`
	Cluster                      string `json:"cluster"`
	NodePool                     string `json:"nodePool,omitempty"`
	NodeClaim                    string `json:"nodeClaim"`
	VMName                       string `json:"vmName"`
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
	FirewallProfile              string `json:"firewallProfile"`
	NetworkUUID                  string `json:"networkUUID"`
	ControlPlaneVIP              string `json:"controlPlaneVIP"`
	PrivateLoadBalancerPoolStart string `json:"privateLoadBalancerPoolStart"`
	PrivateLoadBalancerPoolStop  string `json:"privateLoadBalancerPoolStop"`
	OSName                       string `json:"osName"`
	OSVersion                    string `json:"osVersion"`
	BillingAccountID             int64  `json:"billingAccountID"`
	FloatingIPName               string `json:"floatingIPName"`
	PublicIPv4                   string `json:"publicIPv4,omitempty"`
}

type missingNodeCreateFence struct {
	Schema  string                        `json:"schema"`
	Binding missingNodeCreateFenceBinding `json:"binding"`
	Cleanup missingNodeCleanupIdentity    `json:"cleanup"`
	Token   string                        `json:"token"`
	Phase   string                        `json:"phase"`
	Intent  string                        `json:"intent"`
	IssueID string                        `json:"issueID"`

	StartedAt           string  `json:"startedAt"`
	IssuedAt            *string `json:"issuedAt,omitempty"`
	LaunchObservedAt    *string `json:"launchObservedAt,omitempty"`
	CreatedVMUUID       string  `json:"createdVMUUID"`
	ProtectionFailureAt *string `json:"protectionFailureAt,omitempty"`
	RollbackAt          *string `json:"rollbackAt,omitempty"`
	ObservedAt          *string `json:"observedAt,omitempty"`
	ObservedVMUUID      string  `json:"observedVMUUID"`
	FloatingIPName      string  `json:"floatingIPName"`
	PublicIPv4          string  `json:"publicIPv4"`

	BaseFirewallAssignment *missingNodeFirewallAssignment `json:"baseFirewallAssignment"`
}

type missingNodeCreateFenceBinding struct {
	NodeClaimUID       string `json:"nodeClaimUID"`
	IdempotencyKeyHash string `json:"idempotencyKeyHash"`
	RequestHash        string `json:"requestHash"`
	SpecHash           string `json:"specHash"`
	BootstrapHash      string `json:"bootstrapHash"`
}

type missingNodeCleanupIdentity struct {
	ClusterName                  string `json:"clusterName"`
	Location                     string `json:"location"`
	NetworkUUID                  string `json:"networkUUID"`
	NodePoolName                 string `json:"nodePoolName"`
	ControlPlaneVIP              string `json:"controlPlaneVIP"`
	PrivateLoadBalancerPoolStart string `json:"privateLoadBalancerPoolStart"`
	PrivateLoadBalancerPoolStop  string `json:"privateLoadBalancerPoolStop"`
	FirewallUUID                 string `json:"firewallUUID"`
	FirewallProfile              string `json:"firewallProfile"`
	NodeClaimName                string `json:"nodeClaimName"`
	VMName                       string `json:"vmName"`
	BillingAccountID             int64  `json:"billingAccountID"`
	OwnershipKeyHash             string `json:"ownershipKeyHash"`
}

type missingNodeFirewallAssignment struct {
	VMUUID       string  `json:"vmUUID"`
	FirewallUUID string  `json:"firewallUUID"`
	Phase        string  `json:"phase"`
	IssueID      string  `json:"issueID"`
	IntentAt     string  `json:"intentAt"`
	IssuedAt     *string `json:"issuedAt,omitempty"`
	RejectedAt   *string `json:"rejectedAt,omitempty"`
	ObservedAt   *string `json:"observedAt,omitempty"`
}

// AuthorizeMissingNodeDetach is deliberately detach-only. It establishes two
// independent absence proofs for the old Node and binds one deleting
// NodeClaim, its immutable UID, its durable launch fence, and the current VM
// ownership description to the exact provider ID. Any partial read or identity
// drift is retryable and therefore preserves external-attacher's finalizer.
func (r *KubernetesNodeResolver) AuthorizeMissingNodeDetach(
	ctx context.Context,
	request missingNodeDetachRequest,
) error {
	ownership, err := validateMissingNodeDetachRequest(request)
	if err != nil {
		return missingNodeAuthorityError(err)
	}
	if err := r.requireMissingKubernetesNode(ctx, request.NodeName); err != nil {
		return missingNodeAuthorityError(err)
	}

	claim, err := r.getMissingNodeClaim(ctx, ownership.NodeClaim)
	if err != nil {
		return missingNodeAuthorityError(err)
	}
	if err := validateMissingNodeClaim(claim, request, ownership); err != nil {
		return missingNodeAuthorityError(err)
	}

	listed, err := r.listMissingNodeClaims(ctx)
	if err != nil {
		return missingNodeAuthorityError(err)
	}
	if err := validateMissingNodeClaimInventory(listed, claim, request, ownership); err != nil {
		return missingNodeAuthorityError(err)
	}
	nodes, err := r.listKubernetesNodesForMissingNodeAuthority(ctx)
	if err != nil {
		return missingNodeAuthorityError(err)
	}
	if err := validateMissingNodeInventory(nodes, request); err != nil {
		return missingNodeAuthorityError(err)
	}

	// Re-read the exact claim and the old Node after both bounded inventories.
	// A concurrent claim reincarnation, finalizer release, or Node registration
	// cannot grant detach authority from an older list snapshot.
	readback, err := r.getMissingNodeClaim(ctx, ownership.NodeClaim)
	if err != nil {
		return missingNodeAuthorityError(err)
	}
	if err := validateMissingNodeClaim(readback, request, ownership); err != nil {
		return missingNodeAuthorityError(err)
	}
	if claim.Metadata.UID != readback.Metadata.UID ||
		claim.Metadata.DeletionTimestamp != readback.Metadata.DeletionTimestamp ||
		claim.Status.ProviderID != readback.Status.ProviderID ||
		claim.Status.NodeName != readback.Status.NodeName ||
		claim.Metadata.Annotations[inspaceCreateFenceAnnotation] != readback.Metadata.Annotations[inspaceCreateFenceAnnotation] {
		return missingNodeAuthorityError(errors.New("deleting NodeClaim identity changed during detach authorization"))
	}
	if err := r.requireMissingKubernetesNode(ctx, request.NodeName); err != nil {
		return missingNodeAuthorityError(err)
	}
	return nil
}

func validateMissingNodeDetachRequest(request missingNodeDetachRequest) (missingNodeOwnershipRecord, error) {
	if !nodeNamePattern.MatchString(request.NodeName) {
		return missingNodeOwnershipRecord{}, fmt.Errorf("invalid missing Kubernetes Node name %q", request.NodeName)
	}
	if request.Location != strings.ToLower(strings.TrimSpace(request.Location)) ||
		!missingNodeLocationPattern.MatchString(request.Location) {
		return missingNodeOwnershipRecord{}, fmt.Errorf("non-canonical InSpace location %q", request.Location)
	}
	if request.VMUUID != strings.ToLower(strings.TrimSpace(request.VMUUID)) || !uuidPattern.MatchString(request.VMUUID) {
		return missingNodeOwnershipRecord{}, fmt.Errorf("non-canonical attached VM UUID %q", request.VMUUID)
	}
	if request.DiskUUID != strings.ToLower(strings.TrimSpace(request.DiskUUID)) || !uuidPattern.MatchString(request.DiskUUID) {
		return missingNodeOwnershipRecord{}, fmt.Errorf("non-canonical attached disk UUID %q", request.DiskUUID)
	}
	if request.NetworkUUID != strings.ToLower(strings.TrimSpace(request.NetworkUUID)) || !uuidPattern.MatchString(request.NetworkUUID) {
		return missingNodeOwnershipRecord{}, fmt.Errorf("non-canonical configured network UUID %q", request.NetworkUUID)
	}
	if request.BillingAccountID <= 0 {
		return missingNodeOwnershipRecord{}, errors.New("configured billing account ID must be positive")
	}
	if request.VMName != request.NodeName || request.VMHostname != request.NodeName {
		return missingNodeOwnershipRecord{}, errors.New("exact VM name and guest hostname must both equal the missing Node name")
	}
	if request.VMDescription == "" || len(request.VMDescription) > maxMissingNodeDescriptionBytes {
		return missingNodeOwnershipRecord{}, errors.New("VM ownership description is empty or oversized")
	}
	var ownership missingNodeOwnershipRecord
	if err := decodeMissingNodeAuthorityJSON([]byte(request.VMDescription), &ownership); err != nil {
		return missingNodeOwnershipRecord{}, fmt.Errorf("decode VM ownership: %w", err)
	}
	if err := validateMissingNodeOwnership(ownership, request); err != nil {
		return missingNodeOwnershipRecord{}, err
	}
	return ownership, nil
}

func validateMissingNodeOwnership(ownership missingNodeOwnershipRecord, request missingNodeDetachRequest) error {
	if ownership.Schema != inspaceOwnershipV3 {
		return fmt.Errorf("VM ownership schema %q is not strict v3", ownership.Schema)
	}
	if !missingNodeDNSLabelPattern.MatchString(ownership.Cluster) ||
		!missingNodeDNSLabelPattern.MatchString(ownership.NodeClaim) {
		return errors.New("VM ownership cluster or NodeClaim is not a canonical DNS-1123 label")
	}
	if ownership.VMName != request.NodeName ||
		ownership.Cluster+"-karp-"+ownership.NodeClaim != request.NodeName {
		return errors.New("VM ownership does not derive the exact missing Node name")
	}
	if !missingNodeHex32Pattern.MatchString(ownership.KeyHash) ||
		!missingNodeHex32Pattern.MatchString(ownership.SpecHash) ||
		!missingNodeHex32Pattern.MatchString(ownership.BootstrapHash) {
		return errors.New("VM ownership hash identity is malformed")
	}
	if ownership.HostClass == "" || ownership.InstanceType == "" ||
		ownership.VCPU <= 0 || ownership.MemoryGiB <= 0 || ownership.RootDiskGiB <= 0 ||
		ownership.OSName == "" || ownership.OSVersion == "" ||
		ownership.FloatingIPName == "" {
		return errors.New("VM ownership launch identity is incomplete")
	}
	if ownership.HostPoolUUID != strings.ToLower(strings.TrimSpace(ownership.HostPoolUUID)) ||
		!uuidPattern.MatchString(ownership.HostPoolUUID) {
		return errors.New("VM ownership host-pool UUID is not canonical")
	}
	if ownership.FirewallUUID != strings.ToLower(ownership.FirewallUUID) || !uuidPattern.MatchString(ownership.FirewallUUID) {
		return errors.New("VM ownership firewall UUID is not canonical")
	}
	if ownership.NetworkUUID != request.NetworkUUID ||
		ownership.BillingAccountID != request.BillingAccountID {
		return errors.New("VM ownership account or configured-VPC identity differs")
	}
	if ownership.ControlPlaneVIP == "" ||
		ownership.PrivateLoadBalancerPoolStart == "" ||
		ownership.PrivateLoadBalancerPoolStop == "" {
		return errors.New("VM ownership cluster network identity is incomplete")
	}
	if ownership.PublicIPv4 != "" {
		return errors.New("strict v3 VM ownership unexpectedly records mutable public IPv4 state")
	}
	switch ownership.FirewallProfile {
	case "private-worker":
		if ownership.NodePool != "" {
			return errors.New("private-worker ownership unexpectedly carries a NodePool cleanup identity")
		}
	case "public-node-load-balancer", "public-node-local":
		if ownership.NodePool == "" {
			return errors.New("public worker ownership lacks its NodePool identity")
		}
	default:
		return fmt.Errorf("unsupported VM ownership firewall profile %q", ownership.FirewallProfile)
	}
	return nil
}

func (r *KubernetesNodeResolver) requireMissingKubernetesNode(ctx context.Context, nodeName string) error {
	_, err := r.ProviderIDForNode(ctx, nodeName)
	if errors.Is(err, errKubernetesNodeNotFound) {
		return nil
	}
	if err == nil {
		return fmt.Errorf("Kubernetes Node %q reappeared during detach authorization", nodeName)
	}
	return fmt.Errorf("cannot prove Kubernetes Node %q is absent: %w", nodeName, err)
}

func (r *KubernetesNodeResolver) getMissingNodeClaim(ctx context.Context, name string) (missingNodeClaim, error) {
	path := "/apis/karpenter.sh/v1/nodeclaims/" + url.PathEscape(name)
	status, data, err := r.kubernetesAPIRequestWithLimit(
		ctx,
		http.MethodGet,
		path,
		nil,
		maxMissingNodeAuthorityResponseBytes,
	)
	if err != nil {
		return missingNodeClaim{}, err
	}
	if status != http.StatusOK {
		return missingNodeClaim{}, fmt.Errorf("exact NodeClaim %q GET returned HTTP %d", name, status)
	}
	var claim missingNodeClaim
	if err := decodeMissingNodeAuthorityJSON(data, &claim); err != nil {
		return missingNodeClaim{}, fmt.Errorf("decode exact NodeClaim %q: %w", name, err)
	}
	if claim.APIVersion != karpenterNodeClaimAPIVersion || claim.Kind != karpenterNodeClaimKind ||
		claim.Metadata.Name != name {
		return missingNodeClaim{}, fmt.Errorf("exact NodeClaim %q returned mismatched type or name", name)
	}
	return claim, nil
}

func (r *KubernetesNodeResolver) listMissingNodeClaims(ctx context.Context) ([]missingNodeClaim, error) {
	var result []missingNodeClaim
	seenNames := map[string]struct{}{}
	seenUIDs := map[string]struct{}{}
	resourceVersion := ""
	continueToken := ""
	seenContinueTokens := map[string]struct{}{}
	pages := 0
	for {
		pages++
		if pages > maxMissingNodeClaimAuthorityPages {
			return nil, fmt.Errorf("NodeClaim LIST exceeds bounded maximum of %d pages", maxMissingNodeClaimAuthorityPages)
		}
		query := url.Values{"limit": {fmt.Sprint(missingNodeClaimAuthorityPageSize)}}
		if continueToken != "" {
			query.Set("continue", continueToken)
		}
		status, data, err := r.kubernetesAPIRequestWithLimit(
			ctx,
			http.MethodGet,
			"/apis/karpenter.sh/v1/nodeclaims?"+query.Encode(),
			nil,
			maxMissingNodeAuthorityResponseBytes,
		)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("NodeClaim LIST returned HTTP %d", status)
		}
		var page missingNodeClaimList
		if err := decodeMissingNodeAuthorityJSON(data, &page); err != nil {
			return nil, fmt.Errorf("decode NodeClaim LIST: %w", err)
		}
		if page.APIVersion != karpenterNodeClaimAPIVersion || page.Kind != karpenterNodeClaimListKind ||
			page.Metadata.ResourceVersion == "" {
			return nil, errors.New("NodeClaim LIST returned incomplete type or resourceVersion")
		}
		if resourceVersion == "" {
			resourceVersion = page.Metadata.ResourceVersion
		} else if page.Metadata.ResourceVersion != resourceVersion {
			return nil, errors.New("NodeClaim LIST resourceVersion changed across pagination")
		}
		for _, claim := range page.Items {
			if claim.Metadata.Name == "" || claim.Metadata.UID == "" {
				return nil, errors.New("NodeClaim LIST contains an object without name or UID")
			}
			if _, duplicate := seenNames[claim.Metadata.Name]; duplicate {
				return nil, fmt.Errorf("NodeClaim LIST repeats name %q", claim.Metadata.Name)
			}
			if _, duplicate := seenUIDs[claim.Metadata.UID]; duplicate {
				return nil, fmt.Errorf("NodeClaim LIST repeats UID %q", claim.Metadata.UID)
			}
			seenNames[claim.Metadata.Name] = struct{}{}
			seenUIDs[claim.Metadata.UID] = struct{}{}
			result = append(result, claim)
			if len(result) > maxMissingNodeAuthorityItems {
				return nil, fmt.Errorf("NodeClaim LIST exceeds bounded maximum of %d items", maxMissingNodeAuthorityItems)
			}
		}
		if page.Metadata.Continue == "" {
			return result, nil
		}
		if len(page.Metadata.Continue) > maxMissingNodeContinueTokenBytes {
			return nil, errors.New("NodeClaim LIST returned an oversized continuation token")
		}
		if _, duplicate := seenContinueTokens[page.Metadata.Continue]; duplicate {
			return nil, errors.New("NodeClaim LIST repeated a continuation token")
		}
		seenContinueTokens[page.Metadata.Continue] = struct{}{}
		continueToken = page.Metadata.Continue
	}
}

func (r *KubernetesNodeResolver) listKubernetesNodesForMissingNodeAuthority(
	ctx context.Context,
) ([]missingNodeKubernetesNode, error) {
	var result []missingNodeKubernetesNode
	seenNames := map[string]struct{}{}
	seenUIDs := map[string]struct{}{}
	resourceVersion := ""
	continueToken := ""
	seenContinueTokens := map[string]struct{}{}
	pages := 0
	for {
		pages++
		if pages > maxMissingNodeAuthorityNodePages {
			return nil, fmt.Errorf("Node LIST exceeds bounded maximum of %d pages", maxMissingNodeAuthorityNodePages)
		}
		query := url.Values{"limit": {fmt.Sprint(missingNodeAuthorityNodePageSize)}}
		if continueToken != "" {
			query.Set("continue", continueToken)
		}
		status, data, err := r.kubernetesAPIRequestWithLimit(
			ctx,
			http.MethodGet,
			"/api/v1/nodes?"+query.Encode(),
			nil,
			maxMissingNodeAuthorityResponseBytes,
		)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("Node LIST returned HTTP %d", status)
		}
		var page missingNodeKubernetesNodeList
		if err := decodeMissingNodeAuthorityJSON(data, &page); err != nil {
			return nil, fmt.Errorf("decode Node LIST: %w", err)
		}
		if page.APIVersion != "v1" || page.Kind != "NodeList" || page.Metadata.ResourceVersion == "" {
			return nil, errors.New("Node LIST returned incomplete type or resourceVersion")
		}
		if resourceVersion == "" {
			resourceVersion = page.Metadata.ResourceVersion
		} else if page.Metadata.ResourceVersion != resourceVersion {
			return nil, errors.New("Node LIST resourceVersion changed across pagination")
		}
		for _, node := range page.Items {
			if node.Metadata.Name == "" || node.Metadata.UID == "" {
				return nil, errors.New("Node LIST contains an object without name or UID")
			}
			if _, duplicate := seenNames[node.Metadata.Name]; duplicate {
				return nil, fmt.Errorf("Node LIST repeats name %q", node.Metadata.Name)
			}
			if _, duplicate := seenUIDs[node.Metadata.UID]; duplicate {
				return nil, fmt.Errorf("Node LIST repeats UID %q", node.Metadata.UID)
			}
			seenNames[node.Metadata.Name] = struct{}{}
			seenUIDs[node.Metadata.UID] = struct{}{}
			result = append(result, node)
			if len(result) > maxMissingNodeAuthorityItems {
				return nil, fmt.Errorf("Node LIST exceeds bounded maximum of %d items", maxMissingNodeAuthorityItems)
			}
		}
		if page.Metadata.Continue == "" {
			return result, nil
		}
		if len(page.Metadata.Continue) > maxMissingNodeContinueTokenBytes {
			return nil, errors.New("Node LIST returned an oversized continuation token")
		}
		if _, duplicate := seenContinueTokens[page.Metadata.Continue]; duplicate {
			return nil, errors.New("Node LIST repeated a continuation token")
		}
		seenContinueTokens[page.Metadata.Continue] = struct{}{}
		continueToken = page.Metadata.Continue
	}
}

func validateMissingNodeClaim(
	claim missingNodeClaim,
	request missingNodeDetachRequest,
	ownership missingNodeOwnershipRecord,
) error {
	if claim.APIVersion != karpenterNodeClaimAPIVersion || claim.Kind != karpenterNodeClaimKind ||
		claim.Metadata.Name != ownership.NodeClaim || claim.Metadata.UID == "" ||
		claim.Metadata.ResourceVersion == "" {
		return errors.New("NodeClaim exact identity is incomplete")
	}
	deletingAt, err := time.Parse(time.RFC3339Nano, claim.Metadata.DeletionTimestamp)
	if err != nil || deletingAt.IsZero() {
		return errors.New("NodeClaim is not durably deleting")
	}
	finalizers := map[string]struct{}{}
	for _, finalizer := range claim.Metadata.Finalizers {
		if finalizer == "" {
			return errors.New("NodeClaim has an empty finalizer")
		}
		if _, duplicate := finalizers[finalizer]; duplicate {
			return fmt.Errorf("NodeClaim repeats finalizer %q", finalizer)
		}
		finalizers[finalizer] = struct{}{}
	}
	for _, required := range []string{karpenterTerminationFinalizer, inspaceCreateProtectionFinalizer} {
		if _, present := finalizers[required]; !present {
			return fmt.Errorf("NodeClaim lacks required finalizer %q", required)
		}
	}
	if claim.Metadata.Annotations[inspaceNodeNameAnnotation] != request.NodeName {
		return errors.New("NodeClaim node-name annotation does not match the missing Node")
	}
	if claim.Status.NodeName != request.NodeName {
		return errors.New("NodeClaim status.nodeName does not match the missing Node")
	}
	expectedProviderID := "inspace://" + request.Location + "/" + request.VMUUID
	location, vmUUID, err := parseProviderID(claim.Status.ProviderID)
	if err != nil || claim.Status.ProviderID != expectedProviderID ||
		location != request.Location || vmUUID != request.VMUUID {
		return errors.New("NodeClaim status.providerID does not canonically bind the attached VM")
	}

	conditions := map[string]string{}
	for _, condition := range claim.Status.Conditions {
		if condition.Type == "" || condition.Status == "" {
			return errors.New("NodeClaim contains an incomplete condition")
		}
		if _, duplicate := conditions[condition.Type]; duplicate {
			return fmt.Errorf("NodeClaim repeats condition type %q", condition.Type)
		}
		conditions[condition.Type] = condition.Status
	}
	if conditions[karpenterRegisteredCondition] != "True" {
		return errors.New("NodeClaim Registered condition is not True")
	}
	if _, present := conditions[karpenterTerminatingCondition]; present {
		return errors.New("NodeClaim already has an InstanceTerminating condition")
	}

	encodedFence := claim.Metadata.Annotations[inspaceCreateFenceAnnotation]
	if encodedFence == "" || len(encodedFence) > maxMissingNodeCreateFenceBytes {
		return errors.New("NodeClaim create fence is empty or oversized")
	}
	var fence missingNodeCreateFence
	if err := decodeMissingNodeAuthorityJSON([]byte(encodedFence), &fence); err != nil {
		return fmt.Errorf("decode NodeClaim create fence: %w", err)
	}
	return validateMissingNodeCreateFence(fence, claim, request, ownership)
}

func validateMissingNodeCreateFence(
	fence missingNodeCreateFence,
	claim missingNodeClaim,
	request missingNodeDetachRequest,
	ownership missingNodeOwnershipRecord,
) error {
	if fence.Schema != inspaceCreateFenceV3 || fence.Phase != inspaceCreateFenceMaterialized {
		return errors.New("NodeClaim create fence is not strict materialized v3")
	}
	if fence.Intent != "post" && fence.Intent != "adoption" {
		return errors.New("NodeClaim create fence has an invalid materialization intent")
	}
	if !missingNodeHex32Pattern.MatchString(fence.Token) ||
		!missingNodeHex32Pattern.MatchString(fence.IssueID) ||
		!missingNodeHex64Pattern.MatchString(fence.Binding.IdempotencyKeyHash) ||
		!missingNodeHex64Pattern.MatchString(fence.Binding.RequestHash) {
		return errors.New("NodeClaim create fence hashes or issue identity are malformed")
	}
	uidHash := sha256.Sum256([]byte(claim.Metadata.UID))
	fullUIDHash := hex.EncodeToString(uidHash[:])
	if fence.Binding.NodeClaimUID != claim.Metadata.UID ||
		fence.Binding.IdempotencyKeyHash != fullUIDHash ||
		fence.Binding.SpecHash != ownership.SpecHash ||
		fence.Binding.BootstrapHash != ownership.BootstrapHash {
		return errors.New("NodeClaim create-fence binding does not match UID or VM ownership")
	}
	if fence.Cleanup.ClusterName != ownership.Cluster ||
		fence.Cleanup.Location != request.Location ||
		fence.Cleanup.NetworkUUID != request.NetworkUUID ||
		fence.Cleanup.NodePoolName != ownership.NodePool ||
		fence.Cleanup.ControlPlaneVIP != ownership.ControlPlaneVIP ||
		fence.Cleanup.PrivateLoadBalancerPoolStart != ownership.PrivateLoadBalancerPoolStart ||
		fence.Cleanup.PrivateLoadBalancerPoolStop != ownership.PrivateLoadBalancerPoolStop ||
		fence.Cleanup.FirewallUUID != ownership.FirewallUUID ||
		fence.Cleanup.FirewallProfile != ownership.FirewallProfile ||
		fence.Cleanup.NodeClaimName != claim.Metadata.Name ||
		fence.Cleanup.VMName != request.NodeName ||
		fence.Cleanup.BillingAccountID != request.BillingAccountID ||
		fence.Cleanup.OwnershipKeyHash != ownership.KeyHash ||
		fence.Cleanup.OwnershipKeyHash != fullUIDHash[:32] {
		return errors.New("NodeClaim create-fence cleanup identity does not match the VM, account, or VPC")
	}
	if fence.CreatedVMUUID != request.VMUUID ||
		fence.ObservedVMUUID != request.VMUUID ||
		fence.CreatedVMUUID != strings.ToLower(fence.CreatedVMUUID) ||
		fence.RollbackAt != nil ||
		fence.ProtectionFailureAt != nil {
		return errors.New("NodeClaim create fence lacks one unrolled-back materialized VM identity")
	}
	if fence.FloatingIPName == "" || fence.FloatingIPName != ownership.FloatingIPName ||
		fence.PublicIPv4 == "" {
		return errors.New("NodeClaim create fence lacks its materialized Floating IP identity")
	}
	for field, value := range map[string]*string{
		"issuedAt":         fence.IssuedAt,
		"launchObservedAt": fence.LaunchObservedAt,
		"observedAt":       fence.ObservedAt,
	} {
		if value == nil || !validMissingNodeTimestamp(*value) {
			return fmt.Errorf("NodeClaim create fence has invalid %s", field)
		}
	}
	if !validMissingNodeTimestamp(fence.StartedAt) {
		return errors.New("NodeClaim create fence has invalid startedAt")
	}
	assignment := fence.BaseFirewallAssignment
	if assignment == nil ||
		assignment.Phase != inspaceFirewallAssignmentObserved ||
		assignment.VMUUID != request.VMUUID ||
		assignment.FirewallUUID != fence.Cleanup.FirewallUUID ||
		!missingNodeHex32Pattern.MatchString(assignment.IssueID) ||
		!validMissingNodeTimestamp(assignment.IntentAt) ||
		assignment.IssuedAt == nil || !validMissingNodeTimestamp(*assignment.IssuedAt) ||
		assignment.ObservedAt == nil || !validMissingNodeTimestamp(*assignment.ObservedAt) ||
		assignment.RejectedAt != nil {
		return errors.New("NodeClaim create fence lacks an observed base-firewall assignment")
	}
	return nil
}

func validateMissingNodeClaimInventory(
	claims []missingNodeClaim,
	exact missingNodeClaim,
	request missingNodeDetachRequest,
	ownership missingNodeOwnershipRecord,
) error {
	exactMatches := 0
	providerMatches := 0
	expectedProviderID := "inspace://" + request.Location + "/" + request.VMUUID
	for _, claim := range claims {
		if claim.Metadata.Name == ownership.NodeClaim {
			exactMatches++
			if claim.Metadata.UID != exact.Metadata.UID {
				return errors.New("NodeClaim LIST and exact GET disagree on UID")
			}
			if err := validateMissingNodeClaim(claim, request, ownership); err != nil {
				return fmt.Errorf("listed exact NodeClaim is not authoritative: %w", err)
			}
		}
		rawProviderID := claim.Status.ProviderID
		trimmedProviderID := strings.TrimSpace(rawProviderID)
		if trimmedProviderID == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(trimmedProviderID), "inspace:") {
			continue
		}
		location, vmUUID, err := parseProviderID(rawProviderID)
		if err != nil {
			return fmt.Errorf("NodeClaim %q has malformed InSpace provider ID", claim.Metadata.Name)
		}
		canonicalProviderID := "inspace://" + location + "/" + vmUUID
		if rawProviderID != canonicalProviderID {
			return fmt.Errorf("NodeClaim %q has a non-canonical InSpace provider ID", claim.Metadata.Name)
		}
		if canonicalProviderID == expectedProviderID {
			providerMatches++
			if claim.Metadata.Name != ownership.NodeClaim || claim.Metadata.UID != exact.Metadata.UID {
				return errors.New("another NodeClaim advertises the attached VM provider ID")
			}
		}
	}
	if exactMatches != 1 || providerMatches != 1 {
		return fmt.Errorf(
			"NodeClaim inventory contains %d exact-name and %d exact-provider matches, expected one each",
			exactMatches,
			providerMatches,
		)
	}
	return nil
}

func validateMissingNodeInventory(nodes []missingNodeKubernetesNode, request missingNodeDetachRequest) error {
	expectedProviderID := "inspace://" + request.Location + "/" + request.VMUUID
	for _, node := range nodes {
		if node.Metadata.Name == request.NodeName {
			return fmt.Errorf("Kubernetes Node %q appeared in the bounded inventory", request.NodeName)
		}
		rawProviderID := node.Spec.ProviderID
		trimmedProviderID := strings.TrimSpace(rawProviderID)
		if trimmedProviderID == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(trimmedProviderID), "inspace:") {
			continue
		}
		location, vmUUID, err := parseProviderID(rawProviderID)
		if err != nil {
			return fmt.Errorf("Node %q has malformed InSpace provider ID", node.Metadata.Name)
		}
		canonicalProviderID := "inspace://" + location + "/" + vmUUID
		if rawProviderID != canonicalProviderID {
			return fmt.Errorf("Node %q has a non-canonical InSpace provider ID", node.Metadata.Name)
		}
		if canonicalProviderID == expectedProviderID {
			return fmt.Errorf("Node %q still advertises the attached VM provider ID", node.Metadata.Name)
		}
	}
	return nil
}

func validMissingNodeTimestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !parsed.IsZero()
}

func missingNodeAuthorityError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%w: missing-node detach authorization: %v", cloud.ErrUnavailable, err)
}

func decodeMissingNodeAuthorityJSON(data []byte, destination any) error {
	canonicalKeys, err := missingNodeAuthorityCanonicalJSONKeys(destination)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := validateMissingNodeAuthorityJSONValue(decoder, canonicalKeys); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("invalid trailing JSON: %w", err)
		}
		return fmt.Errorf("unexpected trailing JSON token %v", token)
	}
	if err := json.Unmarshal(data, destination); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	return nil
}

func missingNodeAuthorityCanonicalJSONKeys(destination any) ([]string, error) {
	var keys []string
	visited := map[reflect.Type]struct{}{}
	var visit func(reflect.Type) error
	visit = func(valueType reflect.Type) error {
		for valueType.Kind() == reflect.Pointer ||
			valueType.Kind() == reflect.Slice ||
			valueType.Kind() == reflect.Array {
			valueType = valueType.Elem()
		}
		if valueType.Kind() != reflect.Struct {
			return nil
		}
		if _, ok := visited[valueType]; ok {
			return nil
		}
		visited[valueType] = struct{}{}
		for index := 0; index < valueType.NumField(); index++ {
			field := valueType.Field(index)
			if !field.IsExported() {
				continue
			}
			tag := strings.Split(field.Tag.Get("json"), ",")[0]
			if tag == "-" {
				continue
			}
			if tag == "" {
				tag = field.Name
			}
			known := false
			for _, existing := range keys {
				if strings.EqualFold(existing, tag) {
					if existing != tag {
						return fmt.Errorf("authority JSON schema has case-ambiguous fields %q and %q", existing, tag)
					}
					known = true
					break
				}
			}
			if !known {
				keys = append(keys, tag)
			}
			if err := visit(field.Type); err != nil {
				return err
			}
		}
		return nil
	}
	if destination == nil {
		return nil, errors.New("authority JSON destination is nil")
	}
	if err := visit(reflect.TypeOf(destination)); err != nil {
		return nil, err
	}
	return keys, nil
}

func validateMissingNodeAuthorityJSONValue(
	decoder *json.Decoder,
	canonicalKeys []string,
) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seenExact := map[string]struct{}{}
		var seenFolded []string
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("invalid JSON object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid non-string JSON object key")
			}
			if _, duplicate := seenExact[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seenExact[key] = struct{}{}
			for _, previous := range seenFolded {
				if strings.EqualFold(previous, key) {
					return fmt.Errorf("case-ambiguous JSON object keys %q and %q", previous, key)
				}
			}
			seenFolded = append(seenFolded, key)
			for _, canonical := range canonicalKeys {
				if strings.EqualFold(key, canonical) && key != canonical {
					return fmt.Errorf("non-canonical JSON object key %q; expected %q", key, canonical)
				}
			}
			if err := validateMissingNodeAuthorityJSONValue(decoder, canonicalKeys); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object terminator")
		}
	case '[':
		for decoder.More() {
			if err := validateMissingNodeAuthorityJSONValue(decoder, canonicalKeys); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array terminator")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

var _ missingNodeDetachAuthorizer = (*KubernetesNodeResolver)(nil)
