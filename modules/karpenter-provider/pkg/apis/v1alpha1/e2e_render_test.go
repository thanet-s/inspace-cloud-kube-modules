package v1alpha1

import (
	"os"
	"strings"
	"testing"
)

func TestClusterE2ERendersWorkerSSHAccess(t *testing.T) {
	data, err := os.ReadFile("../../../../../test/e2e/run.sh")
	if err != nil {
		t.Fatalf("read cluster E2E: %v", err)
	}
	script := string(data)
	for _, expected := range []string{
		`sshUsername: $ssh_user`,
		`sshPublicKey: "$configured_public_key"`,
		`ufw allow proto tcp from $management_cidr to any port 22`,
		`wait_until 600 "SSH on Karpenter worker" ssh_ready "$worker_public_ip"`,
		`wait_until 600 "worker cloud-init, Ubuntu 24.04, and K3s agent" k3s_agent_ready "$worker_public_ip"`,
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("cluster E2E does not render %q into its worker NodeClass", expected)
		}
	}
}

func TestClusterE2EProvesWorkerVPCAttachment(t *testing.T) {
	script := readClusterE2E(t)
	vpcCheck := shellFunction(t, script, "owned_worker_vpc_ready", "karpenter_pods_absent")
	for _, gate := range []string{
		`validate_worker_records "$workers"`,
		`[[ $(jq -r 'length' <<<"$workers") == 1 ]]`,
		`worker_uuid=$(jq -er '.[0].uuid'`,
		`worker_name=$(jq -er '.[0].name'`,
		`[[ $worker_name == "$node_name" ]]`,
		`api_get "network/network/$INSPACE_NETWORK_UUID"`,
		`.uuid == $network`,
		`(.vm_uuids | type) == "array"`,
		`([.vm_uuids[] | select(. == $worker)] | length) == 1`,
		`--arg provider "inspace://$INSPACE_LOCATION/$worker_uuid"`,
		`.spec.providerID == $provider`,
		`select(.type == "InternalIP")`,
		`if length == 1 then .[0]`,
		`ipaddress.ip_network(sys.argv[1], strict=False)`,
		`network.subnet_of(prefix)`,
		`address not in network`,
	} {
		if !strings.Contains(vpcCheck, gate) {
			t.Fatalf("worker VPC proof is missing gate %q", gate)
		}
	}
	workerPhaseStart := strings.Index(script, `cat >"$state_dir/karpenter.yaml"`)
	if workerPhaseStart < 0 {
		t.Fatal("cluster E2E is missing the rendered Karpenter resources")
	}
	assertOrdered(t, script[workerPhaseStart:],
		`networkUUID: $INSPACE_NETWORK_UUID`,
		`kubectl apply -f "$state_dir/trigger.yaml"`,
		`kubectl -n default rollout status deployment/inspace-e2e-trigger`,
		`kubectl wait --for=condition=Ready node -l "karpenter.sh/nodepool=$nodepool_name"`,
		`jq -e '.items | length == 1 and all(.[]; any(.status.conditions[]; .type=="Ready" and .status=="True"))'`,
		`kubectl get nodeclaims -l "karpenter.sh/nodepool=$nodepool_name"`,
		`worker_node=$(kubectl get node -l "karpenter.sh/nodepool=$nodepool_name"`,
		`persist_worker_ownership_from_cloud`,
		`jq -e 'length == 1'`,
		`wait_until 300 "Karpenter worker attachment to the configured private VPC"`,
		`owned_worker_vpc_ready "$worker_node"`,
		`worker_public_ip=$(owned_worker_public_ip)`,
		`wait_until 600 "SSH on Karpenter worker"`,
		`wait_until 600 "worker cloud-init, Ubuntu 24.04, and K3s agent"`,
		`rollout status daemonset/inspace-csi-node`,
		`echo "==> verify RWO CSI mount, persistence, and TCP public LoadBalancer"`,
		`kubectl apply -f "$state_dir/workload.yaml"`,
	)
}

func TestClusterE2EDeletesNodeClaimsBeforeNodePool(t *testing.T) {
	script := readClusterE2E(t)
	quiesce := shellFunction(t, script, "kubernetes_e2e_quiesce", "quiesce_kubernetes_e2e_owners_bounded")
	assertOrdered(t, quiesce,
		`delete nodeclaims \`,
		`owned_nodeclaims_absent "$claim_grace_deadline"`,
		`force_finalize_drained_owned_worker "$deadline"`,
		`owned_worker_node_absent "$deadline"`,
		`delete nodepool "$nodepool_name"`,
		`delete inspacenodeclass "$nodeclass_name"`,
	)
}

func TestClusterE2EForcedWorkerCleanupIsGatedAndOrdered(t *testing.T) {
	script := readClusterE2E(t)
	fallback := shellFunction(t, script, "force_finalize_drained_owned_worker", "kubernetes_e2e_quiesce")
	assertOrdered(t, fallback,
		`validate_forced_worker_cleanup_state "$deadline"`,
		`scale deployment inspace-karpenter`,
		`karpenter_pods_absent "$deadline"`,
	)
	if strings.Count(fallback, `validate_forced_worker_cleanup_state "$deadline"`) != 4 {
		t.Fatal("forced cleanup must revalidate after controller shutdown, cloud cleanup, and Node finalization")
	}
	assertOrdered(t, fallback,
		`# fallback. All safety predicates are re-read after its Pods are gone.`,
		`validate_forced_worker_cleanup_state "$deadline"`,
		`cleanup_forced_worker_resources "$deadline"`,
		`forced_worker_resources_absent "$deadline"`,
		`# Bind every finalizer mutation to a post-cloud-cleanup Kubernetes snapshot.`,
		`validate_forced_worker_cleanup_state "$deadline" || return $?`,
		`node_json=$validated_worker_node_json`,
		`patch node "$worker_name"`,
		`owned_worker_node_absent "$deadline"`,
		`validate_forced_worker_cleanup_state "$deadline" || return $?`,
		`claim_json=$validated_worker_claim_json`,
		`patch nodeclaim "$worker_name"`,
		`owned_worker_nodeclaim_absent "$deadline"`,
		`owned_nodeclaims_absent "$deadline"`,
	)
	if strings.Count(fallback, `path:"/metadata/finalizers",value:["karpenter.sh/termination"]`) != 2 {
		t.Fatal("forced cleanup must atomically test exact Node and NodeClaim finalizers")
	}
	for _, identityTest := range []string{`path:"/metadata/uid"`, `path:"/metadata/resourceVersion"`, `path:"/metadata/deletionTimestamp"`} {
		if strings.Count(fallback, identityTest) != 2 {
			t.Fatalf("forced cleanup must atomically test %s for both Node and NodeClaim", identityTest)
		}
	}
	for _, boundedMutation := range []string{
		`--current-replicas="$replicas" --resource-version="$deployment_rv" --replicas=0`,
		`kubectl --request-timeout="${timeout_seconds}s" patch node "$worker_name"`,
		`kubectl --request-timeout="${timeout_seconds}s" patch nodeclaim "$worker_name"`,
	} {
		if !strings.Contains(fallback, boundedMutation) {
			t.Fatalf("forced cleanup is missing bounded identity-bound mutation %q", boundedMutation)
		}
	}
	for _, forbiddenRefresh := range []string{`get node "$worker_name"`, `get nodeclaim "$worker_name"`} {
		if strings.Contains(fallback, forbiddenRefresh) {
			t.Fatalf("forced cleanup refreshes an unvalidated finalizer input with %q", forbiddenRefresh)
		}
	}
	for _, mandatoryGate := range []string{
		`validate_forced_worker_cleanup_state "$deadline" || return $?`,
		`cleanup_forced_worker_resources "$deadline" || return $?`,
		`forced_worker_resources_absent "$deadline" || return $?`,
		`owned_worker_node_absent "$deadline" || return $?`,
		`owned_worker_nodeclaim_absent "$deadline" || return $?`,
		`owned_nodeclaims_absent "$deadline" || return $?`,
	} {
		if !strings.Contains(fallback, mandatoryGate) {
			t.Fatalf("forced cleanup does not fail closed on gate %q", mandatoryGate)
		}
	}
}

func TestClusterE2EForcedWorkerCleanupValidatesOwnershipAndDrainState(t *testing.T) {
	script := readClusterE2E(t)
	validation := shellFunction(t, script, "validate_forced_worker_cleanup_state", "force_finalize_drained_owned_worker")
	for _, gate := range []string{
		`e2e_pods_absent "$deadline"`,
		`pv_and_attachments_absent "$deadline"`,
		`worker_volume_attachments_absent "$deadline" "$worker_name"`,
		`($nodeclass.spec.clusterName == $cluster)`,
		`($nodeclass.spec.networkUUID == $network)`,
		`($claim.status.providerID == ("inspace://" + $location + "/" + $worker.uuid))`,
		`.apiVersion == "karpenter.sh/v1" and .kind == "NodePool"`,
		`.type == "Drained" and .status == "True"`,
		`.type == "VolumesDetached" and .status == "True"`,
		`($ownedNodes[0].metadata.deletionTimestamp != null)`,
		`validated_worker_claim_json=$(jq`,
		`<<<"$claims") || return 2`,
		`validated_worker_node_json=$(jq`,
		`end' <<<"$nodes") || return 2`,
	} {
		if !strings.Contains(validation, gate) {
			t.Fatalf("forced worker cleanup validation is missing gate %q", gate)
		}
	}
}

func TestClusterE2EForcedCloudCleanupUsesOnlyExactPersistedWorker(t *testing.T) {
	script := readClusterE2E(t)
	snapshot := shellFunction(t, script, "forced_worker_cloud_snapshot", "forced_worker_resources_absent")
	for _, gate := range []string{
		`api_get user-resource/vm/list "$deadline"`,
		`api_get network/ip_addresses "$deadline"`,
		`(($ownedVMs | length) <= 1)`,
		`.vm.uuid == $worker.uuid and .vm.name == $worker.name`,
		`.record.schema == "karpenter.inspace.cloud/v1"`,
		`.record.nodeClaim == $worker.name`,
		`.record.floatingIPName == $worker.fip`,
		`(($ownedIPs | length) <= 1)`,
		`.name == $worker.fip`,
		`(.assigned_to == $worker.uuid)`,
		`(.assigned_to_resource_type == "virtual_machine")`,
	} {
		if !strings.Contains(snapshot, gate) {
			t.Fatalf("forced cloud snapshot is missing exact ownership gate %q", gate)
		}
	}
	cleanup := shellFunction(t, script, "cleanup_forced_worker_resources_once", "cleanup_forced_worker_resources")
	assertOrdered(t, cleanup,
		`forced_worker_cloud_snapshot "$deadline"`,
		`api_post_json "network/ip_addresses/$address/unassign" "$deadline"`,
		`api_delete_json "network/ip_addresses/$address" "$deadline"`,
		`api_delete_vm "$uuid" "$deadline"`,
	)
}

func TestClusterE2EParentDeletionAbsenceProofsAreBroad(t *testing.T) {
	script := readClusterE2E(t)
	claims := shellFunction(t, script, "owned_nodeclaims_absent", "persist_service_ownership_from_cluster")
	nodes := shellFunction(t, script, "owned_worker_node_absent", "owned_worker_nodeclaim_absent")
	for name, body := range map[string]string{"NodeClaim": claims, "Node": nodes} {
		for _, gate := range []string{
			`startswith($prefix)`,
			`.metadata.labels["karpenter.sh/nodepool"] == $pool`,
			`any($workers[]; .name ==`,
			`] | length == 0`,
		} {
			if !strings.Contains(body, gate) {
				t.Fatalf("%s absence proof is missing broad ownership gate %q", name, gate)
			}
		}
	}
}

func readClusterE2E(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../../../../test/e2e/run.sh")
	if err != nil {
		t.Fatalf("read cluster E2E: %v", err)
	}
	return string(data)
}

func shellFunction(t *testing.T, script, name, nextName string) string {
	t.Helper()
	startMarker := name + "() {"
	endMarker := "\n" + nextName + "() {"
	start := strings.Index(script, startMarker)
	if start < 0 {
		t.Fatalf("cluster E2E is missing %s", name)
	}
	relativeEnd := strings.Index(script[start:], endMarker)
	if relativeEnd < 0 {
		t.Fatalf("cluster E2E cannot find the end of %s", name)
	}
	return script[start : start+relativeEnd]
}

func assertOrdered(t *testing.T, text string, markers ...string) {
	t.Helper()
	position := 0
	for _, marker := range markers {
		relative := strings.Index(text[position:], marker)
		if relative < 0 {
			t.Fatalf("expected %q after byte %d", marker, position)
		}
		position += relative + len(marker)
	}
}
