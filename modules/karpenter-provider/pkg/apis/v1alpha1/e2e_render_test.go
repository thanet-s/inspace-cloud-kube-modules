package v1alpha1

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
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
		`CONTROLLER_IMAGE=ghcr.io/thanet-s/inspace-cloud-controller-manager@$ccm_platform_digest`,
		`--tag "$runner_image"`,
		"docker run --rm",
		`type=bind,src=$env_file,dst=/run/config/workspace.env,readonly`,
		`type=bind,src=$ssh_private_key,dst=/run/secrets/e2e_ssh_key,readonly`,
		`type=volume,src=$state_volume,dst=/state`,
	} {
		mustContain(t, "host launcher", run, expected)
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
		"run_ansible /opt/e2e/init-cluster.yml",
		"run_ansible /opt/e2e/test.yml",
		"run_ansible /opt/e2e/destroy-cluster.yml",
		`setsid ansible-playbook "$@" --forks 10 &`,
		`kill -TERM -- "-$pid"`,
		"ansible_starting=true",
		"process group identity was not yet stable",
		"phase-preserved",
		"e2e_attach_require_initialized=false",
		"trap 'cleanup_on_signal INT' INT",
		"trap 'cleanup_on_signal TERM' TERM",
	} {
		mustContain(t, "container entrypoint", entrypoint, expected)
	}
}

func TestClusterE2EProvisionsInOrderAndWaitsForThreeControlPlanesInParallel(t *testing.T) {
	clusterTemplate := readE2E(t, "templates/cluster.yaml.j2")
	initPlaybook := readE2E(t, "init-cluster.yml")
	playbook := initPlaybook + "\n" + readE2E(t, "test.yml")
	if err := validateNoJinjaControlDirectives(clusterTemplate); err != nil {
		t.Fatal(err)
	}
	if got := yamlMappingScalar(t, clusterTemplate, "spec", "controlPlane", "replicas"); got != "3" {
		t.Fatalf("cluster template spec.controlPlane.replicas=%q, want exactly 3", got)
	}
	for _, expected := range []string{
		"version: v1.35.6+rke2r1",
		"name: inspace-rke2-agent-token",
		"podCIDR: 10.42.0.0/16",
		"bootstrapCache:",
		"directDownload: false",
		"hostPoolUUID: {{ lookup('env', 'INSPACE_AMD_HOST_POOL_UUID') }}",
	} {
		mustContain(t, "cluster template", clusterTemplate, expected)
	}
	if strings.Contains(strings.ToLower(clusterTemplate), "intel") {
		t.Fatal("cluster template must use only the AMD EPYC host pool")
	}
	for _, expected := range []string{
		"Run the bootstrap reconciler synchronously to readiness",
		"e2e_bootstrap_result.controlPlaneVMs | length == 3",
		"e2e_bootstrap_result.controlPlaneVMs | unique | length == 3",
		"e2e_bootstrap_result.maxParallelControlPlaneCreates | int == 1",
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
		`EnableBPFMasquerade[[:space:]]*:[[:space:]]*true`,
		`EnableIPv4Masquerade[[:space:]]*:[[:space:]]*true`,
	} {
		mustContain(t, "Ansible playbook", playbook, expected)
	}
	plays := parseAnsiblePlays(t, initPlaybook)
	provision := exactAnsiblePlay(t, plays, "Provision the RKE2 control plane through the product bootstrap controller")
	if provision.Hosts != "localhost" {
		t.Fatalf("provision play hosts=%q, want localhost", provision.Hosts)
	}
	launch := exactAnsibleTask(t, provision, "Run the bootstrap reconciler synchronously to readiness")
	launchCommand := requireTaskMapping(t, launch, "ansible.builtin.command")
	requireMappingStringSequence(t, launchCommand, "argv", []string{
		"inspace-cluster-controller",
		"--cluster-config",
		"{{ e2e_cluster_file }}",
		"--ssh-public-key-file",
		"{{ lookup('env', 'E2E_PUBLIC_KEY') }}",
		"--ssh-username",
		"{{ e2e_ssh_user }}",
		"--management-cidr",
		"{{ e2e_management_cidr }}",
		"--management-tcp-ports",
		"22",
		"--until-ready",
		"--interval",
		"15s",
		"--output=json",
	})
	requireTaskScalar(t, launch, "register", "e2e_bootstrap_wait")
	if _, exists := launch["async"]; exists {
		t.Fatal("bootstrap cloud mutation must not use detached Ansible async")
	}
	if _, exists := launch["poll"]; exists {
		t.Fatal("bootstrap cloud mutation must not use detached Ansible polling")
	}
	orderedContract := exactAnsibleTask(t, provision, "Prove exact and ordered three-control-plane provisioning")
	requireTaskAssertions(t, orderedContract,
		"e2e_bootstrap_result.controlPlaneVMs | length == 3",
		"e2e_bootstrap_result.controlPlaneVMs | unique | length == 3",
		"e2e_bootstrap_result.maxParallelControlPlaneCreates | int == 1",
	)
	authoritativeBinding := exactAnsibleTask(t, provision, "Bind the ordered-create contract to the authoritative three VM identities")
	requireTaskAssertions(t, authoritativeBinding,
		"e2e_state.controlPlanes | length == 3",
		"e2e_state.controlPlanes | map(attribute='uuid') | list | unique | length == 3",
		"e2e_state.controlPlanes | map(attribute='uuid') | list | difference(e2e_bootstrap_result.controlPlaneVMs) | length == 0",
		"e2e_bootstrap_result.controlPlaneVMs | difference(e2e_state.controlPlanes | map(attribute='uuid') | list) | length == 0",
		"e2e_bootstrap_result.maxParallelControlPlaneCreates | int == 1",
	)

	bastion := exactAnsiblePlay(t, plays, "Establish the pinned public bastion")
	if bastion.Hosts != "rke2_bastion" {
		t.Fatalf("bastion play hosts=%q, want rke2_bastion", bastion.Hosts)
	}
	if got, ok := bastion.Vars["e2e_release_images"].(string); !ok ||
		got != "{{ hostvars['localhost']['e2e_release_images'] }}" {
		t.Fatalf(
			"bastion release-image manifest=%v, want the immutable localhost fact",
			bastion.Vars["e2e_release_images"],
		)
	}

	controlPlaneWait := exactAnsiblePlay(t, plays, "Wait for all RKE2 servers independently and in parallel through the bastion")
	if controlPlaneWait.Hosts != "rke2_control_plane" || controlPlaneWait.Strategy != "free" {
		t.Fatalf("control-plane wait play hosts/strategy=%q/%q, want rke2_control_plane/free", controlPlaneWait.Hosts, controlPlaneWait.Strategy)
	}
	requireUnserializedParallelPlay(t, controlPlaneWait)
	probe := exactAnsibleTask(t, controlPlaneWait, "Probe every private control-plane SSH port from the bastion in parallel")
	requireParallelTask(t, probe)
	requireTaskModule(t, probe, "ansible.builtin.command")
	requireTaskNumber(t, probe, "retries", 120)
	requireTaskNumber(t, probe, "delay", 5)
	requireTaskScalar(t, probe, "until", "e2e_private_ssh_probe.rc == 0")
	hostKey := exactAnsibleTask(t, controlPlaneWait, "Scan each private control-plane host key from the bastion")
	requireParallelTask(t, hostKey)
	requireTaskModule(t, hostKey, "ansible.builtin.command")
	requireTaskNumber(t, hostKey, "retries", 20)
	requireTaskNumber(t, hostKey, "delay", 5)
	requireTaskScalar(t, hostKey, "until", "e2e_host_keyscan.rc == 0 and e2e_host_keyscan.stdout | length > 0")
	connection := exactAnsibleTask(t, controlPlaneWait, "Wait for authenticated SSH on every control plane in parallel")
	requireParallelTask(t, connection)
	connectionConfig := requireTaskMapping(t, connection, "ansible.builtin.wait_for_connection")
	requireMappingNumber(t, connectionConfig, "connect_timeout", 10)
	requireMappingNumber(t, connectionConfig, "sleep", 5)
	requireMappingNumber(t, connectionConfig, "timeout", 1200)
	cloudInit := exactAnsibleTask(t, controlPlaneWait, "Wait for cloud-init completion on every control plane in parallel")
	requireParallelTask(t, cloudInit)
	requireTaskModule(t, cloudInit, "ansible.builtin.raw")
	mustContain(t, "control-plane cloud-init wait", taskString(t, cloudInit, "ansible.builtin.raw"), "timeout --kill-after=5s 4800s")
	prepared := exactAnsibleTask(t, controlPlaneWait, "Detect completed product node preparation on every control plane")
	requireParallelTask(t, prepared)
	preparedConfig := requireTaskMapping(t, prepared, "ansible.builtin.stat")
	requireMappingString(t, preparedConfig, "path", "/var/lib/inspace/kubernetes-node-prepared-v1")
	disableSwap := exactAnsibleTask(t, controlPlaneWait, "Disable active swap on every control plane in parallel")
	requireParallelTask(t, disableSwap)
	requireTaskModule(t, disableSwap, "ansible.builtin.shell")
	mustContain(t, "control-plane swap disable", taskString(t, disableSwap, "ansible.builtin.shell"), "swapoff -a")
	persistSwap := exactAnsibleTask(t, controlPlaneWait, "Disable persistent swap entries on every control plane in parallel")
	requireParallelTask(t, persistSwap)
	persistSwapConfig := requireTaskMapping(t, persistSwap, "ansible.builtin.replace")
	requireMappingString(t, persistSwapConfig, "regexp", `^(?!\s*#)(.*\s+swap\s+.*)$`)
	mirror := exactAnsibleTask(t, controlPlaneWait, "Configure ordered TOT and KKU Ubuntu mirrors on every control plane in parallel")
	requireParallelTask(t, mirror)
	mirrorConfig := requireTaskMapping(t, mirror, "ansible.builtin.copy")
	requireMappingString(t, mirrorConfig, "dest", "/etc/apt/mirrors/inspace-ubuntu.list")
	requireMappingContains(t, mirrorConfig, "content", `http://mirror1.totbb.net/ubuntu/{{ "\t" }}priority:1`)
	requireMappingContains(t, mirrorConfig, "content", `https://mirror.kku.ac.th/ubuntu/{{ "\t" }}priority:2`)
	sources := exactAnsibleTask(t, controlPlaneWait, "Configure Ubuntu update and security suites on every control plane in parallel")
	requireParallelTask(t, sources)
	sourcesConfig := requireTaskMapping(t, sources, "ansible.builtin.copy")
	requireMappingString(t, sourcesConfig, "dest", "/etc/apt/sources.list.d/ubuntu.sources")
	requireMappingContains(t, sourcesConfig, "content", "Suites: noble-security")
	resolver := exactAnsibleTask(t, controlPlaneWait, "Configure static Google DNS on every control plane in parallel")
	requireParallelTask(t, resolver)
	resolverConfig := requireTaskMapping(t, resolver, "ansible.builtin.copy")
	requireMappingString(t, resolverConfig, "dest", "/etc/resolv.conf")
	requireMappingContains(t, resolverConfig, "content", "nameserver 8.8.8.8")
	resolved := exactAnsibleTask(t, controlPlaneWait, "Disable systemd-resolved on every control plane in parallel")
	requireParallelTask(t, resolved)
	resolvedConfig := requireTaskMapping(t, resolved, "ansible.builtin.systemd_service")
	requireMappingString(t, resolvedConfig, "name", "systemd-resolved.service")
	refresh := exactAnsibleTask(t, controlPlaneWait, "Refresh package indexes without upgrading repaired E2E control planes")
	requireParallelTask(t, refresh)
	refreshConfig := requireTaskMapping(t, refresh, "ansible.builtin.apt")
	requireMappingNumber(t, refreshConfig, "lock_timeout", 300)
	if updateCache, ok := refreshConfig["update_cache"].(bool); !ok || !updateCache {
		t.Fatalf("Ansible refresh update_cache=%#v, want true", refreshConfig["update_cache"])
	}
	if _, found := refreshConfig["upgrade"]; found {
		t.Fatalf("E2E repair unexpectedly restores the skipped OS upgrade: %#v", refreshConfig)
	}
	requireTaskNumber(t, refresh, "async", 600)
	requireTaskNumber(t, refresh, "poll", 10)
	sysctls := exactAnsibleTask(t, controlPlaneWait, "Persist Kubernetes sysctls on repaired control planes")
	requireParallelTask(t, sysctls)
	sysctlCopy := requireTaskMapping(t, sysctls, "ansible.builtin.copy")
	requireMappingString(t, sysctlCopy, "dest", "/etc/sysctl.d/90-inspace-kubernetes.conf")
	limits := exactAnsibleTask(t, controlPlaneWait, "Persist Kubernetes PAM limits on repaired control planes")
	requireParallelTask(t, limits)
	limitsCopy := requireTaskMapping(t, limits, "ansible.builtin.copy")
	requireMappingString(t, limitsCopy, "dest", "/etc/security/limits.d/90-inspace-kubernetes.conf")
	dropInDirectory := exactAnsibleTask(t, controlPlaneWait, "Create the repaired RKE2 server drop-in directory")
	requireParallelTask(t, dropInDirectory)
	dropInDirectoryConfig := requireTaskMapping(t, dropInDirectory, "ansible.builtin.file")
	requireMappingString(t, dropInDirectoryConfig, "path", "/etc/systemd/system/rke2-server.service.d")
	requireMappingString(t, dropInDirectoryConfig, "state", "directory")
	serviceLimits := exactAnsibleTask(t, controlPlaneWait, "Persist RKE2 server limits on repaired control planes")
	requireParallelTask(t, serviceLimits)
	serviceLimitsCopy := requireTaskMapping(t, serviceLimits, "ansible.builtin.copy")
	requireMappingString(t, serviceLimitsCopy, "dest", "/etc/systemd/system/rke2-server.service.d/20-inspace-node-limits.conf")
	restartRepaired := exactAnsibleTask(t, controlPlaneWait, "Restart repaired RKE2 servers one at a time and prove local readiness")
	requireTaskModule(t, restartRepaired, "ansible.builtin.shell")
	requireTaskNumber(t, restartRepaired, "throttle", 1)
	restartScript := taskString(t, restartRepaired, "ansible.builtin.shell")
	for _, expected := range []string{"old_pid=$(systemctl show rke2-server.service --property=MainPID --value)", `test "$new_pid" != "$old_pid"`, "systemctl restart --no-block rke2-server.service", "restart_deadline=$(( $(date +%s) + 1200 ))", "timeout 10s", "[+]etcd ok", "sysctl -n net.ipv4.ip_forward", "LimitNOFILE"} {
		mustContain(t, "rolling repaired-server restart", restartScript, expected)
	}
	persistRepaired := exactAnsibleTask(t, controlPlaneWait, "Persist completed repaired node preparation")
	requireParallelTask(t, persistRepaired)
	persistRepairedConfig := requireTaskMapping(t, persistRepaired, "ansible.builtin.file")
	requireMappingString(t, persistRepairedConfig, "path", "/var/lib/inspace/kubernetes-node-prepared-v1")
	requireMappingString(t, persistRepairedConfig, "state", "touch")
	service := exactAnsibleTask(t, controlPlaneWait, "Wait for every rke2-server service in parallel")
	requireParallelTask(t, service)
	requireTaskModule(t, service, "ansible.builtin.command")
	requireTaskNumber(t, service, "retries", 180)
	requireTaskNumber(t, service, "delay", 10)
	requireTaskScalar(t, service, "until", "e2e_rke2_service.rc == 0 and e2e_rke2_service.stdout == 'active'")
	readyz := exactAnsibleTask(t, controlPlaneWait, "Wait for embedded etcd and the local API on every server in parallel")
	requireParallelTask(t, readyz)
	requireTaskModule(t, readyz, "ansible.builtin.shell")
	requireTaskNumber(t, readyz, "retries", 120)
	requireTaskNumber(t, readyz, "delay", 10)
	requireTaskScalar(t, readyz, "until", "e2e_local_readyz.rc == 0")
	assertOrdered(t, playbook,
		"Run the bootstrap reconciler synchronously to readiness",
		"Prove exact and ordered three-control-plane provisioning",
		"Add exactly three dynamic RKE2 control-plane hosts",
		"Wait for all RKE2 servers independently and in parallel",
		"Require exactly three independently ready RKE2 servers",
	)
}

func TestClusterE2ERendersRKE2WorkerAndCiliumKubeProxyReplacement(t *testing.T) {
	workerTemplate := readE2E(t, "templates/karpenter.yaml.j2")
	playbook := readE2E(t, "init-cluster.yml") + "\n" + readE2E(t, "test.yml")
	for _, expected := range []string{
		"rke2:",
		"version: v1.35.6+rke2r1",
		"server: {{ e2e_bootstrap_result.privateRegistrationEndpoint }}",
		"name: inspace-rke2-agent-token",
		"key: inspace.cloud/instance-cpu",
		`values: ["1"]`,
		"key: inspace.cloud/host-class",
		"values: [amd-epyc]",
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
	if strings.Contains(workerTemplate, "hostPoolSelector") {
		t.Fatal("Karpenter E2E template must select hardware class in NodePool, not NodeClass")
	}
	familyPattern := regexp.MustCompile(`(?m)^\s*- key: inspace\.cloud/instance-family\s*$\n^\s+operator: In\s*$\n^\s+values: \[general\]\s*$`)
	if matches := familyPattern.FindAllString(workerTemplate, -1); len(matches) != 1 {
		t.Fatalf("Karpenter E2E template must contain exactly one general-family requirement so no extra-memory shape is selected, got %d", len(matches))
	}
	cpuPattern := regexp.MustCompile(`(?m)^\s*- key: inspace\.cloud/instance-cpu\s*$\n^\s+operator: Gt\s*$\n^\s+values: \["1"\]\s*$`)
	if matches := cpuPattern.FindAllString(workerTemplate, -1); len(matches) != 1 {
		t.Fatalf("Karpenter E2E general pool must contain exactly one instance-cpu Gt [\"1\"] requirement so no 1-vCPU shape is selected, got %d", len(matches))
	}
	if strings.Contains(workerTemplate, "key: inspace.cloud/instance-memory") {
		t.Fatal("Karpenter E2E template must not constrain instance-memory")
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
		`.data["enable-ipv4-masquerade"] == "true"`,
		`.data["enable-bpf-masquerade"] == "true"`,
		`values["bpf"]["masquerade"] is True`,
		`(.spec | has("hostPoolSelector") | not)`,
		`.status.hostPoolUUIDs | sort`,
		`.key == "inspace.cloud/host-class"`,
		`.metadata.labels["inspace.cloud/instance-cpu"] == "2"`,
		`.metadata.labels["inspace.cloud/instance-memory"] == "4096"`,
		`INSPACE_AMD_HOST_POOL_UUID`,
		`all(.items[]; .metadata.name != "kube-proxy")`,
		`all(.items[]; (.metadata.name | startswith("kube-proxy-")) | not)`,
		"KubeProxyReplacement:[[:space:]]+True",
		"(Routing:.*Native|Direct Routing)",
		"Masquerading:[[:space:]]+BPF",
		"EnableBPFMasquerade",
		"EnableIPv4Masquerade",
		"/etc/sysctl.d/90-inspace-kubernetes.conf",
		"/etc/security/limits.d/90-inspace-kubernetes.conf",
		"LimitMEMLOCK",
	} {
		mustContain(t, "Ansible playbook", playbook, expected)
	}
}

func TestClusterE2EProvesWorkerCloudIdentityAndVPCAttachment(t *testing.T) {
	playbook := readE2E(t, "init-cluster.yml") + "\n" + readE2E(t, "test.yml")
	discovery := readE2E(t, "scripts/discover-worker.py")
	for _, expected := range []string{
		"Read the exact Karpenter worker identity",
		"Persist exact worker cloud ownership and VPC proof",
		`.status.nodeName == $nodeName`,
		`test "$(hostname)" = "{{ e2e_node_name }}"`,
		"/opt/e2e/scripts/discover-worker.py",
		"Add the dynamically created RKE2 worker for parallel-safe validation",
	} {
		mustContain(t, "Ansible playbook", playbook, expected)
	}
	for _, expected := range []string{
		`if len(matches) != 1:`,
		`canonical_worker_vm_detail(`,
		`node.get("name"), node.get("nodeClaimName"), cluster, nodepool`,
		`record.get("schema") != "karpenter.inspace.cloud/v3"`,
		`record.get("nodeClaim") != node.get("nodeClaimName")`,
		`record.get("vmName") != node.get("name")`,
		`vm.get("hostname") != node.get("name")`,
		`VM_UUID_PATTERN.fullmatch(vm_uuid)`,
		`node.get("providerID") != f"inspace://{location}/{vm_uuid}"`,
		`if not isinstance(internal_ips, list) or len(internal_ips) != 1:`,
		`network_uuid = os.environ["INSPACE_NETWORK_UUID"]`,
		`network = api_get(f"network/network/{network_uuid}")`,
		`list(network.get("vm_uuids", [])).count(vm_uuid) != 1`,
		`subnet = ipaddress.ip_network(network["subnet"], strict=False)`,
		`if internal_ip not in subnet:`,
		`if len(named_addresses) != 1:`,
		`record.get("publicIPv4") not in (None, "")`,
		`vm.get("public_ipv4") not in (None, "")`,
		`if node_external_ip != public_ip:`,
		`amd_pool_uuid = os.environ["INSPACE_AMD_HOST_POOL_UUID"]`,
		`record.get("hostClass") != "amd-epyc"`,
		`vm.get("designated_pool_uuid") != amd_pool_uuid`,
		`"publicIPv4": str(public_ip)`,
	} {
		mustContain(t, "worker discovery", discovery, expected)
	}
}

func TestClusterE2ECleanupIsBoundedFailClosedAndOrdered(t *testing.T) {
	entrypoint := readE2E(t, "scripts/container-entrypoint.sh")
	cleanup := readE2E(t, "destroy-cluster.yml")
	for _, expected := range []string{
		"suite_status=$?",
		"cleanup_status=0",
		"if [[ $INSPACE_E2E_KEEP_RESOURCES == true ]]",
		"cleanup_current_run ||",
		"(( cleanup_status == 0 && retention_status == 0 )) || exit 1",
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
		"Destroy only bootstrap-controller-owned infrastructure synchronously",
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
		"Destroy only bootstrap-controller-owned infrastructure synchronously",
		"Require the final deterministic cloud audit to converge to zero",
	)
}

type ansiblePlay struct {
	Name      string           `json:"name"`
	Hosts     string           `json:"hosts"`
	Strategy  string           `json:"strategy"`
	Vars      map[string]any   `json:"vars"`
	Tasks     []map[string]any `json:"tasks"`
	HasSerial bool             `json:"-"`
}

func validateHostLauncherTraceAllowList(trace string) error {
	traceLine := regexp.MustCompile(`^\++ (.*)$`)
	assignment := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=.*$`)
	allowed := map[string]bool{
		"set": true, "[[": true, "case": true, "cd": true, "pwd": true, "docker": true,
	}
	traced := 0
	for _, line := range strings.Split(trace, "\n") {
		match := traceLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		traced++
		commandLine := match[1]
		commandWord := strings.Fields(commandLine)[0]
		if commandWord == "command" && commandLine != "command -v docker" && commandLine != "command -v git" {
			return fmt.Errorf("host launcher command builtin is restricted to exact command -v docker/git: %s", commandLine)
		}
		isSourceVerifier := strings.HasPrefix(commandLine, "/bin/bash test/e2e/scripts/verify-release-source.sh ")
		if !assignment.MatchString(commandLine) &&
			commandLine != "command -v docker" &&
			commandLine != "command -v git" &&
			!isSourceVerifier &&
			!allowed[commandWord] {
			return fmt.Errorf("host launcher executed a command outside the Docker/builtin allow-list: %s", commandLine)
		}
	}
	if traced == 0 {
		return fmt.Errorf("host launcher produced no Bash execution trace")
	}
	return nil
}

func validateNoJinjaControlDirectives(document string) error {
	for _, delimiter := range []string{"{%", "{#"} {
		if strings.Contains(document, delimiter) {
			return fmt.Errorf("cluster template must not contain Jinja control flow or template comments (%s)", delimiter)
		}
	}
	return nil
}

func TestHostLauncherTraceAllowListRejectsCommandBuiltinBypasses(t *testing.T) {
	valid := "+ command -v docker\n+ command -v git\n+ /bin/bash test/e2e/scripts/verify-release-source.sh 0.0.0-static\n+ docker volume inspect static-contract-state\n"
	if err := validateHostLauncherTraceAllowList(valid); err != nil {
		t.Fatalf("valid trace rejected: %v", err)
	}
	for _, trace := range []string{
		"+ command -p docker\n",
		"+ command -p -v docker\n",
		"+ command /usr/bin/curl https://example.invalid\n",
		"+ /usr/bin/docker version\n",
	} {
		if err := validateHostLauncherTraceAllowList(trace); err == nil {
			t.Fatalf("bypass trace accepted: %q", trace)
		}
	}
}

func TestClusterTemplateRejectsHiddenReplicaControlFlow(t *testing.T) {
	for _, document := range []string{
		"{% if false %}\nspec:\n  controlPlane:\n    replicas: 3\n{% endif %}\n",
		"{# spec:\n  controlPlane:\n    replicas: 3 #}\n",
	} {
		if err := validateNoJinjaControlDirectives(document); err == nil {
			t.Fatalf("template control-flow bypass accepted: %q", document)
		}
	}
	if err := validateNoJinjaControlDirectives("spec:\n  controlPlane:\n    replicas: 3\n    name: {{ e2e_name }}\n"); err != nil {
		t.Fatalf("ordinary Jinja value expression rejected: %v", err)
	}
}

func TestParallelAnsibleGuardsRejectSerializationControls(t *testing.T) {
	plays := parseAnsiblePlays(t, `
- name: parallel
  hosts: all
  strategy: free
  serial: 1
  tasks: []
`)
	if err := validateUnserializedParallelPlay(plays[0]); err == nil {
		t.Fatal("serial was accepted on a parallel play")
	}
	for _, key := range []string{"run_once", "throttle"} {
		task := map[string]any{"name": "parallel wait", key: 1}
		if err := validateParallelTask(task); err == nil {
			t.Fatalf("%s was accepted on a parallel wait task", key)
		}
	}
}

func yamlMappingScalar(t *testing.T, document string, path ...string) string {
	t.Helper()
	type parent struct {
		indent int
		key    string
	}
	var stack []parent
	var matches []string
	for lineNumber, line := range strings.Split(document, "\n") {
		if strings.Contains(line, "\t") {
			t.Fatalf("YAML template line %d contains a tab", lineNumber+1)
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "-") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		colon := strings.IndexByte(trimmed, ':')
		if colon <= 0 {
			continue
		}
		key := trimmed[:colon]
		if strings.ContainsAny(key, " {}[]\"'") {
			continue
		}
		for len(stack) != 0 && indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}
		currentPath := make([]string, 0, len(stack)+1)
		for _, item := range stack {
			currentPath = append(currentPath, item.key)
		}
		currentPath = append(currentPath, key)
		value := strings.TrimSpace(trimmed[colon+1:])
		if equalStrings(currentPath, path) {
			if value == "" {
				t.Fatalf("YAML path %s is a mapping, want scalar", strings.Join(path, "."))
			}
			matches = append(matches, value)
		}
		if value == "" {
			stack = append(stack, parent{indent: indent, key: key})
		}
	}
	if len(matches) != 1 {
		t.Fatalf("YAML path %s matched %d times, want exactly once", strings.Join(path, "."), len(matches))
	}
	return matches[0]
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func parseAnsiblePlays(t *testing.T, playbook string) []ansiblePlay {
	t.Helper()
	var plays []ansiblePlay
	if err := yaml.Unmarshal([]byte(playbook), &plays); err != nil {
		t.Fatalf("parse Ansible playbook YAML: %v", err)
	}
	var rawPlays []map[string]any
	if err := yaml.Unmarshal([]byte(playbook), &rawPlays); err != nil {
		t.Fatalf("parse raw Ansible playbook YAML: %v", err)
	}
	if len(rawPlays) != len(plays) {
		t.Fatalf("typed/raw Ansible play counts differ: %d/%d", len(plays), len(rawPlays))
	}
	for index := range plays {
		_, plays[index].HasSerial = rawPlays[index]["serial"]
	}
	if len(plays) == 0 {
		t.Fatal("Ansible playbook contains no plays")
	}
	return plays
}

func exactAnsiblePlay(t *testing.T, plays []ansiblePlay, name string) ansiblePlay {
	t.Helper()
	var matches []ansiblePlay
	for _, play := range plays {
		if play.Name == name {
			matches = append(matches, play)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("Ansible play %q matched %d times, want exactly once", name, len(matches))
	}
	return matches[0]
}

func exactAnsibleTask(t *testing.T, play ansiblePlay, name string) map[string]any {
	t.Helper()
	var matches []map[string]any
	for _, task := range play.Tasks {
		if taskName, _ := task["name"].(string); taskName == name {
			matches = append(matches, task)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("Ansible task %q in play %q matched %d times, want exactly once", name, play.Name, len(matches))
	}
	return matches[0]
}

func requireTaskModule(t *testing.T, task map[string]any, module string) {
	t.Helper()
	if _, exists := task[module]; !exists {
		t.Fatalf("Ansible task %q lacks module %q", task["name"], module)
	}
}

func requireTaskMapping(t *testing.T, task map[string]any, key string) map[string]any {
	t.Helper()
	value, exists := task[key]
	if !exists {
		t.Fatalf("Ansible task %q lacks %q", task["name"], key)
	}
	mapping, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("Ansible task %q field %q has type %T, want mapping", task["name"], key, value)
	}
	return mapping
}

func requireParallelTask(t *testing.T, task map[string]any) {
	t.Helper()
	if err := validateParallelTask(task); err != nil {
		t.Fatal(err)
	}
}

func validateParallelTask(task map[string]any) error {
	for _, forbidden := range []string{"run_once", "throttle"} {
		if _, exists := task[forbidden]; exists {
			return fmt.Errorf("parallel Ansible task %q must not set %s", task["name"], forbidden)
		}
	}
	return nil
}

func requireUnserializedParallelPlay(t *testing.T, play ansiblePlay) {
	t.Helper()
	if err := validateUnserializedParallelPlay(play); err != nil {
		t.Fatal(err)
	}
}

func validateUnserializedParallelPlay(play ansiblePlay) error {
	if play.HasSerial {
		return fmt.Errorf("parallel Ansible play %q must not set serial", play.Name)
	}
	return nil
}

func requireMappingString(t *testing.T, mapping map[string]any, key, expected string) {
	t.Helper()
	value, exists := mapping[key]
	if !exists {
		t.Fatalf("mapping lacks string field %q", key)
	}
	actual, ok := value.(string)
	if !ok {
		t.Fatalf("mapping field %q has type %T, want string", key, value)
	}
	if actual != expected {
		t.Fatalf("mapping field %q=%q, want %q", key, actual, expected)
	}
}

func requireMappingContains(t *testing.T, mapping map[string]any, key, expected string) {
	t.Helper()
	value, exists := mapping[key]
	if !exists {
		t.Fatalf("mapping lacks string field %q", key)
	}
	actual, ok := value.(string)
	if !ok {
		t.Fatalf("mapping field %q has type %T, want string", key, value)
	}
	if !strings.Contains(actual, expected) {
		t.Fatalf("mapping field %q does not contain %q: %q", key, expected, actual)
	}
}

func requireMappingStringSequence(t *testing.T, mapping map[string]any, key string, expected []string) {
	t.Helper()
	raw, exists := mapping[key]
	if !exists {
		t.Fatalf("mapping lacks sequence field %q", key)
	}
	values, ok := raw.([]any)
	if !ok {
		t.Fatalf("mapping field %q has type %T, want sequence", key, raw)
	}
	actual := make([]string, 0, len(values))
	for index, value := range values {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("mapping field %q item %d has type %T, want string", key, index, value)
		}
		actual = append(actual, text)
	}
	if !equalStrings(actual, expected) {
		t.Fatalf("mapping field %q=%q, want %q", key, actual, expected)
	}
}

func requireTaskNumber(t *testing.T, task map[string]any, key string, expected int) {
	t.Helper()
	requireMappingNumber(t, task, key, expected)
}

func requireMappingNumber(t *testing.T, mapping map[string]any, key string, expected int) {
	t.Helper()
	value, exists := mapping[key]
	if !exists {
		t.Fatalf("mapping lacks numeric field %q", key)
	}
	var actual int
	switch typed := value.(type) {
	case float64:
		actual = int(typed)
		if typed != float64(actual) {
			t.Fatalf("mapping field %q=%v is not an integer", key, typed)
		}
	case int:
		actual = typed
	default:
		t.Fatalf("mapping field %q has type %T, want integer", key, value)
	}
	if actual != expected {
		t.Fatalf("mapping field %q=%d, want %d", key, actual, expected)
	}
}

func requireTaskScalar(t *testing.T, task map[string]any, key, expected string) {
	t.Helper()
	if actual := taskString(t, task, key); actual != expected {
		t.Fatalf("Ansible task %q field %q=%q, want %q", task["name"], key, actual, expected)
	}
}

func taskString(t *testing.T, task map[string]any, key string) string {
	t.Helper()
	value, exists := task[key]
	if !exists {
		t.Fatalf("Ansible task %q lacks %q", task["name"], key)
	}
	actual, ok := value.(string)
	if !ok {
		t.Fatalf("Ansible task %q field %q has type %T, want string", task["name"], key, value)
	}
	return actual
}

func requireTaskAssertions(t *testing.T, task map[string]any, expected ...string) {
	t.Helper()
	assertion := requireTaskMapping(t, task, "ansible.builtin.assert")
	raw, exists := assertion["that"]
	if !exists {
		t.Fatalf("Ansible assertion task %q lacks that", task["name"])
	}
	values, ok := raw.([]any)
	if !ok {
		t.Fatalf("Ansible assertion task %q that has type %T, want sequence", task["name"], raw)
	}
	actual := make(map[string]bool, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("Ansible assertion task %q contains non-string clause %T", task["name"], value)
		}
		actual[text] = true
	}
	for _, clause := range expected {
		if !actual[clause] {
			t.Errorf("Ansible assertion task %q lacks exact clause %q", task["name"], clause)
		}
	}
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
