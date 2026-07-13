package v1alpha1

import (
	"os"
	"os/exec"
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
		`CONTROLLER_IMAGE=ghcr.io/thanet-s/inspace-cloud-controller-manager:$INSPACE_E2E_VERSION`,
		`--tag "$runner_image"`,
		"docker run --rm",
		`type=bind,src=$env_file,dst=/run/config/workspace.env,readonly`,
		`type=bind,src=$ssh_private_key,dst=/run/secrets/e2e_ssh_key,readonly`,
		`type=volume,src=$state_volume,dst=/state`,
	} {
		mustContain(t, "host launcher", run, expected)
	}
	assertHostLauncherExternalCommandAllowList(t, runPath)

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
	if got := yamlMappingScalar(t, clusterTemplate, "spec", "controlPlane", "replicas"); got != "3" {
		t.Fatalf("cluster template spec.controlPlane.replicas=%q, want exactly 3", got)
	}
	for _, expected := range []string{
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
	plays := parseAnsiblePlays(t, playbook)
	provision := exactAnsiblePlay(t, plays, "Provision the RKE2 control plane through the product bootstrap controller")
	if provision.Hosts != "localhost" {
		t.Fatalf("provision play hosts=%q, want localhost", provision.Hosts)
	}
	launch := exactAnsibleTask(t, provision, "Launch the bootstrap reconciler asynchronously")
	requireTaskModule(t, launch, "ansible.builtin.command")
	requireTaskNumber(t, launch, "async", 2700)
	requireTaskNumber(t, launch, "poll", 0)
	wait := exactAnsibleTask(t, provision, "Wait robustly for the product reconciler to finish")
	requireTaskModule(t, wait, "ansible.builtin.async_status")
	requireTaskScalar(t, wait, "until", "e2e_bootstrap_wait.finished")
	requireTaskNumber(t, wait, "retries", 270)
	requireTaskNumber(t, wait, "delay", 10)
	parallelContract := exactAnsibleTask(t, provision, "Prove exact and parallel three-control-plane provisioning")
	requireTaskAssertions(t, parallelContract,
		"e2e_bootstrap_result.controlPlaneVMs | length == 3",
		"e2e_bootstrap_result.controlPlaneVMs | unique | length == 3",
		"e2e_bootstrap_result.maxParallelControlPlaneCreates | int == 3",
	)
	authoritativeBinding := exactAnsibleTask(t, provision, "Bind the parallel-create contract to the authoritative three VM identities")
	requireTaskAssertions(t, authoritativeBinding,
		"e2e_state.controlPlanes | length == 3",
		"e2e_state.controlPlanes | map(attribute='uuid') | list | unique | length == 3",
		"e2e_state.controlPlanes | map(attribute='uuid') | list | difference(e2e_bootstrap_result.controlPlaneVMs) | length == 0",
		"e2e_bootstrap_result.controlPlaneVMs | difference(e2e_state.controlPlanes | map(attribute='uuid') | list) | length == 0",
		"(e2e_bootstrap_result.maxParallelControlPlaneCreates | int) == (e2e_state.controlPlanes | length)",
	)

	controlPlaneWait := exactAnsiblePlay(t, plays, "Wait for all RKE2 servers independently and in parallel through the bastion")
	if controlPlaneWait.Hosts != "rke2_control_plane" || controlPlaneWait.Strategy != "free" {
		t.Fatalf("control-plane wait play hosts/strategy=%q/%q, want rke2_control_plane/free", controlPlaneWait.Hosts, controlPlaneWait.Strategy)
	}
	probe := exactAnsibleTask(t, controlPlaneWait, "Probe every private control-plane SSH port from the bastion in parallel")
	requireTaskModule(t, probe, "ansible.builtin.command")
	requireTaskNumber(t, probe, "retries", 120)
	requireTaskNumber(t, probe, "delay", 5)
	requireTaskScalar(t, probe, "until", "e2e_private_ssh_probe.rc == 0")
	hostKey := exactAnsibleTask(t, controlPlaneWait, "Scan each private control-plane host key from the bastion")
	requireTaskModule(t, hostKey, "ansible.builtin.command")
	requireTaskNumber(t, hostKey, "retries", 20)
	requireTaskNumber(t, hostKey, "delay", 5)
	requireTaskScalar(t, hostKey, "until", "e2e_host_keyscan.rc == 0 and e2e_host_keyscan.stdout | length > 0")
	connection := exactAnsibleTask(t, controlPlaneWait, "Wait for authenticated SSH on every control plane in parallel")
	connectionConfig := requireTaskMapping(t, connection, "ansible.builtin.wait_for_connection")
	requireMappingNumber(t, connectionConfig, "connect_timeout", 10)
	requireMappingNumber(t, connectionConfig, "sleep", 5)
	requireMappingNumber(t, connectionConfig, "timeout", 1200)
	cloudInit := exactAnsibleTask(t, controlPlaneWait, "Wait for cloud-init completion on every control plane in parallel")
	requireTaskModule(t, cloudInit, "ansible.builtin.raw")
	mustContain(t, "control-plane cloud-init wait", taskString(t, cloudInit, "ansible.builtin.raw"), "timeout --kill-after=5s 1800s")
	service := exactAnsibleTask(t, controlPlaneWait, "Wait for every rke2-server service in parallel")
	requireTaskModule(t, service, "ansible.builtin.command")
	requireTaskNumber(t, service, "retries", 180)
	requireTaskNumber(t, service, "delay", 10)
	requireTaskScalar(t, service, "until", "e2e_rke2_service.rc == 0 and e2e_rke2_service.stdout == 'active'")
	readyz := exactAnsibleTask(t, controlPlaneWait, "Wait for embedded etcd and the local API on every server in parallel")
	requireTaskModule(t, readyz, "ansible.builtin.shell")
	requireTaskNumber(t, readyz, "retries", 120)
	requireTaskNumber(t, readyz, "delay", 10)
	requireTaskScalar(t, readyz, "until", "e2e_local_readyz.rc == 0")
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

type ansiblePlay struct {
	Name     string           `json:"name"`
	Hosts    string           `json:"hosts"`
	Strategy string           `json:"strategy"`
	Tasks    []map[string]any `json:"tasks"`
}

func assertHostLauncherExternalCommandAllowList(t *testing.T, runPath string) {
	t.Helper()
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dockerLog := filepath.Join(dir, "docker.log")
	unknownLog := filepath.Join(dir, "unknown.log")
	dockerPath := filepath.Join(binDir, "docker")
	if err := os.WriteFile(dockerPath, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$E2E_DOCKER_LOG\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	bashEnv := filepath.Join(dir, "bash-env")
	if err := os.WriteFile(bashEnv, []byte("command_not_found_handle() { printf '%s\\n' \"$1\" >> \"$E2E_UNKNOWN_COMMAND_LOG\"; return 127; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"workspace.env": "INSPACE_API_TOKEN=not-a-real-token\n",
		"id_rsa":        "not-a-real-private-key\n",
		"id_rsa.pub":    "ssh-ed25519 not-a-real-public-key\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	absoluteRunPath, err := filepath.Abs(runPath)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/bash", "-x", absoluteRunPath)
	command.Env = []string{
		"PATH=" + binDir,
		"HOME=" + dir,
		"BASH_ENV=" + bashEnv,
		"E2E_DOCKER_LOG=" + dockerLog,
		"E2E_UNKNOWN_COMMAND_LOG=" + unknownLog,
		"INSPACE_E2E_ENV_FILE=" + filepath.Join(dir, "workspace.env"),
		"INSPACE_E2E_SSH_PRIVATE_KEY=" + filepath.Join(dir, "id_rsa"),
		"INSPACE_E2E_SSH_PUBLIC_KEY=" + filepath.Join(dir, "id_rsa.pub"),
		"INSPACE_E2E_STATE_VOLUME=static-contract-state",
		"CONFIRM_INSPACE_CLUSTER_E2E=static-contract-account",
		"INSPACE_E2E_VERSION=0.0.0-static",
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("host launcher failed with a Docker-only PATH: %v\n%s", err, output)
	}
	assertHostLauncherTraceAllowList(t, string(output))
	if unknown, err := os.ReadFile(unknownLog); err == nil && len(strings.TrimSpace(string(unknown))) != 0 {
		t.Fatalf("host launcher attempted non-Docker external commands: %s", unknown)
	} else if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	logBytes, err := os.ReadFile(dockerLog)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimSpace(string(logBytes)), "\n")
	if len(calls) != 3 || !strings.HasPrefix(calls[0], "volume inspect ") || !strings.HasPrefix(calls[1], "build ") || !strings.HasPrefix(calls[2], "run ") {
		t.Fatalf("host launcher Docker call sequence=%q, want volume inspect, build, run", calls)
	}
}

func assertHostLauncherTraceAllowList(t *testing.T, trace string) {
	t.Helper()
	traceLine := regexp.MustCompile(`^\++ (.*)$`)
	assignment := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=.*$`)
	allowed := map[string]bool{
		"set": true, "[[": true, "case": true, "cd": true, "pwd": true, "command": true, "docker": true,
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
		if !assignment.MatchString(commandLine) && !allowed[commandWord] {
			t.Fatalf("host launcher executed a command outside the Docker/builtin allow-list: %s", commandLine)
		}
	}
	if traced == 0 {
		t.Fatal("host launcher produced no Bash execution trace")
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
