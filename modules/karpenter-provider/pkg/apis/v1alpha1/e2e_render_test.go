package v1alpha1

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const e2eRoot = "../../../../../test/e2e"

func TestClusterE2EHostEntrypointOnlyLaunchesDocker(t *testing.T) {
	runPath := filepath.Join(e2eRoot, "run.sh")
	run := readE2E(t, "run.sh")
	info, err := os.Stat(runPath)
	if err != nil {
		t.Fatalf("stat cluster E2E launcher: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("cluster E2E launcher must be executable because the root Makefile invokes it directly")
	}
	for _, expected := range []string{
		"command -v docker",
		`docker volume inspect "$state_volume"`,
		`docker volume create "$state_volume"`,
		`--file test/e2e/Dockerfile`,
		`--target published-live`,
		`CONTROLLER_IMAGE=ghcr.io/thanet-s/inspace-cloud-controller-manager:$INSPACE_E2E_VERSION`,
		`--tag "$runner_image"`,
		"docker run --rm",
		`type=bind,src=$env_file,dst=/run/config/workspace.env,readonly`,
		`type=bind,src=$ssh_private_key,dst=/run/secrets/e2e_ssh_key,readonly`,
		`type=volume,src=$state_volume,dst=/state`,
	} {
		mustContain(t, "host launcher", run, expected)
	}
	for _, forbidden := range []string{
		"ansible-playbook", "kubectl ", "helm ", "curl ", "python3 ", "ssh-keygen ", "go test", "go build", `source "$env_file"`, "--init", "--env-file",
	} {
		if strings.Contains(run, forbidden) {
			t.Fatalf("host launcher executes non-Docker tooling %q", forbidden)
		}
	}

	dockerfile := readE2E(t, "Dockerfile")
	entrypoint := readE2E(t, "scripts/container-entrypoint.sh")
	for _, expected := range []string{
		"FROM ubuntu:26.04",
		"COPY test/e2e /opt/e2e",
		`ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/opt/e2e/scripts/container-entrypoint.sh"]`,
		"FROM base AS local-validation",
		"FROM base AS published-live",
		"COPY --from=published-controller /usr/local/bin/inspace-cluster-controller",
	} {
		mustContain(t, "runner Dockerfile", dockerfile, expected)
	}
	for _, expected := range []string{
		"run_ansible /opt/e2e/playbook.yml",
		"run_ansible /opt/e2e/cleanup.yml",
		`ansible-playbook "$@" --forks 10 &`,
		"trap 'cleanup_on_signal INT' INT",
		"trap 'cleanup_on_signal TERM' TERM",
	} {
		mustContain(t, "container entrypoint", entrypoint, expected)
	}
}

func TestClusterE2EProvisionsAndWaitsForThreeControlPlanesInParallel(t *testing.T) {
	clusterTemplate := readE2E(t, "templates/cluster.yaml.j2")
	playbook := readE2E(t, "playbook.yml")
	for _, expected := range []string{
		"replicas: 3",
		"version: v1.35.6+rke2r1",
		"name: inspace-rke2-agent-token",
		"podCIDR: 10.42.0.0/16",
		"virtualIPv4:",
	} {
		mustContain(t, "cluster template", clusterTemplate, expected)
	}
	for _, expected := range []string{
		"async: 2700",
		"poll: 0",
		"ansible.builtin.async_status:",
		"until: e2e_bootstrap_wait.finished",
		"retries: 270",
		"e2e_bootstrap_result.controlPlaneVMs | length == 3",
		"e2e_bootstrap_result.controlPlaneVMs | unique | length == 3",
		"e2e_bootstrap_result.maxParallelControlPlaneCreates | int == 3",
		"e2e_bootstrap_result.apiLoadBalancerUUID is not defined",
		"e2e_bootstrap_result.registrationLoadBalancerUUID is not defined",
		"e2e_bootstrap_result.privateRegistrationEndpoint == 'https://' + e2e_virtual_ip + ':9345'",
		"e2e_bootstrap_result.bastionVMUUID | length > 0",
		"groups['rke2_control_plane'] | length == 3",
		"hosts: rke2_control_plane",
		"strategy: free",
		"ansible.builtin.wait_for:",
		"ansible.builtin.wait_for_connection:",
		"until: e2e_rke2_service.rc == 0 and e2e_rke2_service.stdout == 'active'",
		"until: e2e_local_readyz.rc == 0",
	} {
		mustContain(t, "Ansible playbook", playbook, expected)
	}
	assertOrdered(t, playbook,
		"Launch the bootstrap reconciler asynchronously",
		"Wait robustly for the product reconciler to finish",
		"Prove exact and parallel three-control-plane provisioning",
		"Add exactly three dynamic RKE2 control-plane hosts",
		"Wait for all RKE2 servers independently and in parallel",
		"Require exactly three independently ready RKE2 servers",
	)
}

func TestClusterE2ERendersRKE2WorkerAndCiliumKubeProxyReplacement(t *testing.T) {
	workerTemplate := readE2E(t, "templates/karpenter.yaml.j2")
	playbook := readE2E(t, "playbook.yml")
	for _, expected := range []string{
		"rke2:",
		"version: v1.35.6+rke2r1",
		"server: {{ e2e_bootstrap_result.privateRegistrationEndpoint }}",
		"name: inspace-rke2-agent-token",
		"sshUsername: {{ e2e_ssh_user }}",
		"sshPublicKey: {{ e2e_ssh_public_key | to_json }}",
	} {
		mustContain(t, "Karpenter template", workerTemplate, expected)
	}
	for _, forbidden := range []string{"k3s", "ufw", "iptables", "nft"} {
		if strings.Contains(strings.ToLower(workerTemplate), forbidden) {
			t.Fatalf("Karpenter E2E template retained forbidden host bootstrap artifact %q", forbidden)
		}
	}
	for _, expected := range []string{
		"--management-cidr",
		"--management-tcp-ports",
		`- "22"`,
		"systemctl is-active --quiet rke2-agent",
		"/usr/local/bin/rke2 --version | grep -F 'v1.35.6+rke2r1'",
		"Verify Cilium native routing and full kube-proxy replacement",
		`.data["routing-mode"] == "native"`,
		`.data["ipv4-native-routing-cidr"] == "10.42.0.0/16"`,
		`.data["kube-proxy-replacement"] == "true"`,
		`all(.items[]; .metadata.name != "kube-proxy")`,
		`all(.items[]; (.metadata.name | startswith("kube-proxy-")) | not)`,
		"KubeProxyReplacement:[[:space:]]+True",
		"(Routing:.*Native|Direct Routing)",
	} {
		mustContain(t, "Ansible playbook", playbook, expected)
	}
}

func TestClusterE2EProvesWorkerCloudIdentityAndVPCAttachment(t *testing.T) {
	playbook := readE2E(t, "playbook.yml")
	discovery := readE2E(t, "scripts/discover-worker.py")
	for _, expected := range []string{
		"Read the exact Karpenter worker identity",
		"Persist exact worker cloud ownership and VPC proof",
		"/opt/e2e/scripts/discover-worker.py",
		"Add the dynamically created RKE2 worker for parallel-safe validation",
	} {
		mustContain(t, "Ansible playbook", playbook, expected)
	}
	for _, expected := range []string{
		`if len(matches) != 1:`,
		`node.get("providerID") != f"inspace://{location}/{vm_uuid}"`,
		`if not isinstance(internal_ips, list) or len(internal_ips) != 1:`,
		`network_uuid = os.environ["INSPACE_NETWORK_UUID"]`,
		`network = api_get(f"network/network/{network_uuid}")`,
		`list(network.get("vm_uuids", [])).count(vm_uuid) != 1`,
		`subnet = ipaddress.ip_network(network["subnet"], strict=False)`,
		`if internal_ip not in subnet:`,
		`if len(addresses) != 1:`,
		`"publicIPv4": str(public_ip)`,
	} {
		mustContain(t, "worker discovery", discovery, expected)
	}
}

func TestClusterE2ECleanupIsBoundedFailClosedAndOrdered(t *testing.T) {
	entrypoint := readE2E(t, "scripts/container-entrypoint.sh")
	cleanup := readE2E(t, "cleanup.yml")
	for _, expected := range []string{
		"suite_status=$?",
		"cleanup_status=0",
		"if [[ $INSPACE_E2E_KEEP_RESOURCES == true ]]",
		"ansible-playbook /opt/e2e/cleanup.yml --forks 10",
		"if (( cleanup_status != 0 ))",
		`exit "$suite_status"`,
	} {
		mustContain(t, "container entrypoint", entrypoint, expected)
	}
	for _, expected := range []string{
		"cloud infrastructure is the fail-closed outcome",
		"retries: 180",
		"delay: 10",
		"until: e2e_cleanup_storage_quiesced.rc == 0",
		"until: e2e_cleanup_worker_quiesced.rc == 0",
		"async: 1800",
		"poll: 0",
		"ansible.builtin.async_status:",
		"until: e2e_destroy_wait.finished",
		"retries: 90",
		"until: (e2e_final_audit.stdout | from_json).count == 0",
	} {
		mustContain(t, "cleanup playbook", cleanup, expected)
	}
	assertOrdered(t, cleanup,
		"Refuse cloud deletion while Kubernetes API reachability is uncertain",
		"Delete workload owners before infrastructure owners",
		"Wait for E2E pods PVs and VolumeAttachments to disappear",
		"Delete the NodePool while Karpenter is still running",
		"Wait for owned NodeClaims and worker Nodes to disappear",
		"Delete the NodeClass after all worker ownership is gone",
		"Wait until CCM CSI and Karpenter removed all non-control-plane cloud resources",
		"Uninstall controllers only after their owners are quiescent",
		"Remove E2E credentials after controller shutdown",
		"Destroy only bootstrap-controller-owned infrastructure asynchronously",
		"Wait robustly for bootstrap destroy convergence",
		"Require the final deterministic cloud audit to converge to zero",
	)
}

func readE2E(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(e2eRoot, name))
	if err != nil {
		t.Fatalf("read E2E artifact %s: %v", name, err)
	}
	return string(data)
}

func mustContain(t *testing.T, subject, value, expected string) {
	t.Helper()
	if !strings.Contains(value, expected) {
		t.Fatalf("%s is missing %q", subject, expected)
	}
}

func assertOrdered(t *testing.T, value string, fragments ...string) {
	t.Helper()
	position := 0
	for _, fragment := range fragments {
		offset := strings.Index(value[position:], fragment)
		if offset < 0 {
			t.Fatalf("artifact is missing ordered fragment %q after byte %d", fragment, position)
		}
		position += offset + len(fragment)
	}
}
