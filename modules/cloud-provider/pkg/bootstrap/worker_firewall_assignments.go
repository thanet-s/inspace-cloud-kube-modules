package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	inspace "github.com/thanet-s/inspace-cloud-kube-modules/modules/client"
	"github.com/thanet-s/inspace-cloud-kube-modules/modules/cloud-provider/api/v1alpha1"
)

// karpenterWorkerOwnership is the subset of the Karpenter provider's JSON
// ownership record (modules/karpenter-provider/pkg/cloud/inspace) that binds a
// worker VM to one cluster and to the bootstrap node firewall. Node
// load-balancer VMs are ordinary Karpenter workers with the same record.
type karpenterWorkerOwnership struct {
	Schema           string `json:"schema"`
	Cluster          string `json:"cluster"`
	NodeClaim        string `json:"nodeClaim"`
	VMName           string `json:"vmName"`
	FirewallUUID     string `json:"firewallUUID"`
	BillingAccountID int64  `json:"billingAccountID"`
	NetworkUUID      string `json:"networkUUID"`
}

var karpenterWorkerOwnershipSchemas = map[string]bool{
	"karpenter.inspace.cloud/v1": true,
	"karpenter.inspace.cloud/v2": true,
	"karpenter.inspace.cloud/v3": true,
}

func karpenterWorkerNamePrefix(clusterName string) string {
	return clusterName + "-karp-"
}

// nodeFirewallAllowedAssignments returns the exact control-plane assignment
// set extended by VM assignments that provably belong to this cluster's
// Karpenter workers. Karpenter and node load-balancer workers are deliberately
// attached to the bootstrap node firewall, so re-running bootstrap after they
// exist must not report them as drift. A worker is accepted only when the
// location inventory and its exact detail agree on the UUID and the
// "<cluster>-karp-<nodeClaim>" name, and its ownership record names this
// cluster, this node firewall, the configured billing account, and the
// configured VPC. Every other assignment stays outside the allowed set and is
// rejected by validateOwnedFirewallAssignments. The bastion firewall has no
// such tolerance, and Destroy never treats workers as its own.
func (r *Reconciler) nodeFirewallAllowedAssignments(
	ctx context.Context,
	cluster *v1alpha1.InSpaceCluster,
	nodeFirewall *inspace.Firewall,
	listed []inspace.VM,
	controlPlanes map[string]bool,
) (map[string]bool, error) {
	allowed := make(map[string]bool, len(controlPlanes))
	for uuid, ok := range controlPlanes {
		allowed[uuid] = ok
	}
	if nodeFirewall == nil {
		return allowed, nil
	}
	prefix := karpenterWorkerNamePrefix(cluster.Metadata.Name)
	for _, resource := range nodeFirewall.ResourcesAssigned {
		if resource.ResourceType != "vm" || allowed[resource.ResourceUUID] {
			continue
		}
		var row *inspace.VM
		for i := range listed {
			if !strings.EqualFold(listed[i].UUID, resource.ResourceUUID) {
				continue
			}
			if row != nil {
				return nil, fmt.Errorf("bootstrap: node firewall VM assignment %s appears multiple times in the location inventory", resource.ResourceUUID)
			}
			row = &listed[i]
		}
		if row == nil {
			// A worker Karpenter just deleted can keep its firewall relation
			// briefly after leaving the inventory. Never accept it; retry.
			return nil, fmt.Errorf("%w: node firewall VM assignment %s is not in the location VM inventory",
				ErrCreateAttemptPending, resource.ResourceUUID)
		}
		if !strings.HasPrefix(row.Name, prefix) {
			continue
		}
		detail, err := r.API.GetVM(ctx, cluster.Spec.Location, row.UUID)
		if err != nil {
			if inspace.IsNotFound(err) {
				return nil, fmt.Errorf("%w: node firewall worker VM %q detail is not visible", ErrCreateAttemptPending, row.Name)
			}
			return nil, fmt.Errorf("bootstrap: read node firewall worker VM %q: %w", row.Name, err)
		}
		if !karpenterWorkerOwnedByCluster(detail, row, cluster, nodeFirewall.UUID) {
			continue
		}
		allowed[resource.ResourceUUID] = true
	}
	return allowed, nil
}

func karpenterWorkerOwnedByCluster(detail, listed *inspace.VM, cluster *v1alpha1.InSpaceCluster, nodeFirewallUUID string) bool {
	if detail == nil || listed == nil || !vmUUIDPattern.MatchString(detail.UUID) ||
		!strings.EqualFold(detail.UUID, listed.UUID) || detail.Name != listed.Name {
		return false
	}
	prefix := karpenterWorkerNamePrefix(cluster.Metadata.Name)
	if !strings.HasPrefix(detail.Name, prefix) || detail.BillingAccountID != cluster.Spec.BillingAccountID ||
		(detail.NetworkUUID != "" && !strings.EqualFold(detail.NetworkUUID, cluster.Spec.Network.UUID)) {
		return false
	}
	var record karpenterWorkerOwnership
	if err := json.Unmarshal([]byte(detail.Description), &record); err != nil {
		return false
	}
	return karpenterWorkerOwnershipSchemas[record.Schema] &&
		record.Cluster == cluster.Metadata.Name &&
		record.NodeClaim != "" && detail.Name == prefix+record.NodeClaim &&
		(record.VMName == "" || record.VMName == detail.Name) &&
		nodeFirewallUUID != "" && strings.EqualFold(record.FirewallUUID, nodeFirewallUUID) &&
		record.BillingAccountID == cluster.Spec.BillingAccountID &&
		(record.NetworkUUID == "" || strings.EqualFold(record.NetworkUUID, cluster.Spec.Network.UUID))
}
