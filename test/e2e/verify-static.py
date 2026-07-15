#!/usr/bin/env python3
"""Static contract test for the destructive E2E harness; never touches cloud state."""

import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent


def repository_root() -> pathlib.Path:
    """Resolve checkout assets when this test runs from the E2E image."""
    configured = os.environ.get("INSPACE_E2E_SOURCE_ROOT")
    if configured:
        return pathlib.Path(configured).resolve()
    return ROOT.parent.parent


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def manifest_document(text: str, kind: str, name: str) -> str:
    matches = [
        document
        for document in text.split("\n---\n")
        if re.search(rf"(?m)^kind: {re.escape(kind)}$", document)
        and re.search(rf"(?m)^  name: {re.escape(name)}$", document)
    ]
    require(len(matches) == 1, f"expected one {kind}/{name} manifest, found {len(matches)}")
    return matches[0]


def load_script_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_worker_egress_runtime() -> None:
    """Exercise overlap and cleanup ordering against a stateful fake kubectl."""
    smoke_test = ROOT / "scripts/test-ensure-worker-egress.py"
    result = subprocess.run(
        [sys.executable, str(smoke_test)],
        capture_output=True,
        text=True,
        check=False,
    )
    require(
        result.returncode == 0,
        f"worker egress runtime smoke failed:\n{result.stdout}{result.stderr}",
    )


def yaml_mapping_scalar(document: str, *path: str) -> str:
    """Read one scalar at an exact indentation-defined YAML mapping path."""
    stack: list[tuple[int, str]] = []
    matches: list[str] = []
    for line_number, line in enumerate(document.splitlines(), start=1):
        require("\t" not in line, f"YAML template line {line_number} contains a tab")
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        indent = len(line) - len(line.lstrip(" "))
        key_match = re.match(r"^([A-Za-z0-9_-]+):(.*)$", stripped)
        if key_match is None:
            continue
        while stack and indent <= stack[-1][0]:
            stack.pop()
        key, raw_value = key_match.groups()
        value = raw_value.strip()
        current_path = tuple(item[1] for item in stack) + (key,)
        if current_path == path:
            require(value != "", f"YAML path {'.'.join(path)} is not a scalar")
            matches.append(value)
        if value == "":
            stack.append((indent, key))
    require(len(matches) == 1, f"YAML path {'.'.join(path)} matched {len(matches)} times")
    return matches[0]


def named_yaml_sequence_item(document: str, name: str, indent: int) -> str:
    """Return one named play/task block, bounded by its YAML sequence indentation."""
    lines = document.splitlines()
    marker = " " * indent + f"- name: {name}"
    starts = [index for index, line in enumerate(lines) if line == marker]
    require(len(starts) == 1, f"YAML sequence item {name!r} matched {len(starts)} times")
    start = starts[0]
    next_item = re.compile(rf"^ {{{indent}}}- name: ")
    stop = next((index for index in range(start + 1, len(lines)) if next_item.match(lines[index])), len(lines))
    return "\n".join(lines[start:stop])


def require_yaml_key(block: str, indent: int, key: str, value: str) -> None:
    pattern = rf"(?m)^ {{{indent}}}{re.escape(key)}: {re.escape(value)}$"
    require(re.search(pattern, block) is not None, f"YAML block lacks exact {key}: {value}")


def yaml_scalar_sequence(block: str, indent: int, key: str) -> list[str]:
    """Read one exact-format scalar sequence from a bounded YAML block."""
    lines = block.splitlines()
    marker = " " * indent + f"{key}:"
    starts = [index for index, line in enumerate(lines) if line == marker]
    require(len(starts) == 1, f"YAML sequence {key!r} matched {len(starts)} times")
    values: list[str] = []
    item_prefix = " " * (indent + 2) + "- "
    for line in lines[starts[0] + 1:]:
        if not line.strip():
            continue
        current_indent = len(line) - len(line.lstrip(" "))
        if current_indent <= indent:
            break
        require(line.startswith(item_prefix), f"YAML sequence {key!r} contains a non-scalar item: {line}")
        values.append(line[len(item_prefix):])
    require(values, f"YAML sequence {key!r} is empty")
    return values


def require_unrestricted_parallel_task(block: str) -> None:
    """Reject task-level controls that would serialize a free-strategy wait."""
    for key in ("run_once", "throttle"):
        require(
            re.search(rf"(?m)^ {{6}}{key}:", block) is None,
            f"parallel task must not set {key}",
        )


def verify_host_launcher_external_allow_list() -> None:
    """Execute default and shell paths with Docker as the only PATH command."""
    for inspect_fails, phase in ((False, None), (True, None), (False, "shell")):
      with tempfile.TemporaryDirectory(prefix="inspace-e2e-static-") as temporary:
        root = pathlib.Path(temporary)
        bin_dir = root / "bin"
        bin_dir.mkdir(mode=0o700)
        docker_log = root / "docker.log"
        unknown_log = root / "unknown.log"
        docker = bin_dir / "docker"
        docker.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$*\" >> \"$E2E_DOCKER_LOG\"\n"
            "if [ \"${E2E_DOCKER_INSPECT_FAIL:-false}\" = true ] && "
            "[ \"$1\" = volume ] && [ \"$2\" = inspect ]; then\n"
            "  exit 1\n"
            "fi\n",
            encoding="utf-8",
        )
        docker.chmod(0o700)
        bash_env = root / "bash-env"
        bash_env.write_text(
            "command_not_found_handle() { printf '%s\\n' \"$1\" >> \"$E2E_UNKNOWN_COMMAND_LOG\"; return 127; }\n",
            encoding="utf-8",
        )
        bash_env.chmod(0o600)
        inputs = {
            "workspace.env": "INSPACE_API_TOKEN=not-a-real-token\n",
            "id_rsa": "not-a-real-private-key\n",
            "id_rsa.pub": "ssh-ed25519 not-a-real-public-key\n",
        }
        for name, contents in inputs.items():
            path = root / name
            path.write_text(contents, encoding="utf-8")
            path.chmod(0o600)
        environment = {
            "PATH": str(bin_dir),
            "HOME": str(root),
            "BASH_ENV": str(bash_env),
            "E2E_DOCKER_LOG": str(docker_log),
            "E2E_UNKNOWN_COMMAND_LOG": str(unknown_log),
            "E2E_DOCKER_INSPECT_FAIL": str(inspect_fails).lower(),
            "INSPACE_E2E_ENV_FILE": str(root / "workspace.env"),
            "INSPACE_E2E_SSH_PRIVATE_KEY": str(root / "id_rsa"),
            "INSPACE_E2E_SSH_PUBLIC_KEY": str(root / "id_rsa.pub"),
            "INSPACE_E2E_STATE_VOLUME": "static-contract-state",
            "CONFIRM_INSPACE_CLUSTER_E2E": "static-contract-account",
            "INSPACE_E2E_VERSION": "0.0.0-static",
        }
        command = ["/bin/bash", "-x", str(ROOT / "run.sh")]
        if phase is not None:
            command.append(phase)
        result = subprocess.run(
            command,
            cwd=ROOT.parent.parent,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        require(result.returncode == 0, f"host launcher failed with Docker-only PATH: {result.stderr}")
        traced_commands = []
        for line in result.stderr.splitlines():
            match = re.match(r"^\++ (.*)$", line)
            if match is not None:
                traced_commands.append(match.group(1))
        require(traced_commands, "host launcher produced no Bash execution trace")
        allowed_builtins = {"set", "[[", "case", "cd", "pwd", "docker"}
        for command_line in traced_commands:
            command_word = command_line.split(maxsplit=1)[0]
            assignment = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", command_line)
            require(
                command_word != "command" or command_line == "command -v docker",
                f"host launcher command builtin is restricted to exact command -v docker: {command_line}",
            )
            require(
                assignment is not None or command_line == "command -v docker" or command_word in allowed_builtins,
                f"host launcher executed a command outside the Docker/builtin allow-list: {command_line}",
            )
        unknown = unknown_log.read_text(encoding="utf-8").strip() if unknown_log.exists() else ""
        require(not unknown, f"host launcher attempted non-Docker external commands: {unknown}")
        calls = docker_log.read_text(encoding="utf-8").splitlines()
        expected_calls = ["volume inspect static-contract-state"]
        if inspect_fails:
            expected_calls.append("volume create static-contract-state")
        expected_calls.extend([
            "build --platform linux/amd64 --file test/e2e/Dockerfile --target published-live "
            "--build-arg CONTROLLER_IMAGE=ghcr.io/thanet-s/inspace-cloud-controller-manager:0.0.0-static "
            "--tag inspace-cloud-rke2-e2e:local .",
            " ".join((
                "run --rm" + (" -it" if phase == "shell" else "") + " --platform linux/amd64",
                "--env CONFIRM_INSPACE_CLUSTER_E2E=static-contract-account",
                "--env INSPACE_E2E_VERSION=0.0.0-static",
                "--env INSPACE_E2E_KEEP_RESOURCES=false",
                "--env INSPACE_E2E_RUN_ID=",
                "--env INSPACE_E2E_RECOVER_RETAINED=false",
                f"--mount type=bind,src={root / 'workspace.env'},dst=/run/config/workspace.env,readonly",
                f"--mount type=bind,src={root / 'id_rsa'},dst=/run/secrets/e2e_ssh_key,readonly",
                f"--mount type=bind,src={root / 'id_rsa.pub'},dst=/run/secrets/e2e_ssh_key.pub,readonly",
                "--mount type=volume,src=static-contract-state,dst=/state",
                f"inspace-cloud-rke2-e2e:local {phase or 'all'}",
            )),
        ])
        require(
            calls == expected_calls,
            f"unexpected host Docker call sequence: got {calls!r}, want {expected_calls!r}",
        )


def verify_retention_state_parser(entrypoint: str) -> None:
    """Exercise the exact parser used before unfinished-run recovery."""
    function = re.search(r"(?ms)^read_retention_state\(\) \{\n.*?^\}\n", entrypoint)
    require(function is not None, "entrypoint lacks a testable retention-state parser")
    require(
        entrypoint.count('read_retention_state "$directory/state.json"') == 1,
        "all retention decisions must use the tested retention-state parser",
    )
    require("jq -er '.retained // false'" not in entrypoint,
            "unfinished-run recovery must not restore jq -e boolean parsing")
    harness = "set -euo pipefail\n" + function.group(0) + '\nread_retention_state "$1"\n'

    valid_cases = [
        ({}, "false"),
        ({"retained": False}, "false"),
        ({"retained": True}, "true"),
    ]
    invalid_cases = [
        "",
        "{not-json",
        "{}\n{}",
        json.dumps([]),
        json.dumps({"retained": None}),
        json.dumps({"retained": "false"}),
        json.dumps({"retained": 0}),
        json.dumps({"retained": []}),
        json.dumps({"retained": {}}),
    ]

    with tempfile.TemporaryDirectory(prefix="inspace-retention-static-") as temporary:
        state = pathlib.Path(temporary) / "state.json"
        for value, expected in valid_cases:
            state.write_text(json.dumps(value), encoding="utf-8")
            result = subprocess.run(
                ["/bin/bash", "-c", harness, "retention-parser", str(state)],
                capture_output=True,
                text=True,
                check=False,
            )
            require(result.returncode == 0,
                    f"valid retention state {value!r} failed closed: {result.stderr}")
            require(result.stdout.strip() == expected,
                    f"valid retention state {value!r} produced {result.stdout!r}, want {expected!r}")

        for contents in invalid_cases:
            state.write_text(contents, encoding="utf-8")
            result = subprocess.run(
                ["/bin/bash", "-c", harness, "retention-parser", str(state)],
                capture_output=True,
                text=True,
                check=False,
            )
            require(result.returncode != 0,
                    f"malformed or non-boolean retention state was accepted: {contents!r}")


def verify_node_load_balancer_helm_contract() -> None:
    """Prove chart defaults, rendered wiring, examples, and fail-closed gates."""
    repository = repository_root()
    chart = repository / "charts/inspace-cloud-kube-modules"
    values_path = chart / "values.yaml"
    ci_values = chart / "ci/test-values.yaml"
    values = values_path.read_text(encoding="utf-8")

    require(yaml_mapping_scalar(values, "ccm", "nodeLoadBalancer", "enabled") == "true",
            "chart must enable the CCM node-load-balancer controller by default")
    require(yaml_mapping_scalar(values, "ccm", "nodeLoadBalancer", "nodesPerShard") == "1",
            "chart node-load-balancer shards must default to one node")
    require(yaml_mapping_scalar(values, "karpenter", "featureGates", "staticCapacity") == "true",
            "chart must enable Karpenter StaticCapacity for managed node-load-balancer shards")

    render_command = [
        "helm", "template", "verify", str(chart), "--namespace", "kube-system",
        "--values", str(ci_values),
    ]
    rendered_result = subprocess.run(
        render_command,
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )
    require(
        rendered_result.returncode == 0,
        f"Node-LB Helm render failed:\n{rendered_result.stdout}{rendered_result.stderr}",
    )
    rendered = rendered_result.stdout
    ccm_deployment = manifest_document(
        rendered, "Deployment", "verify-inspace-cloud-kube-modules-ccm"
    )
    for variable, value in (
        ("INSPACE_NODE_LOAD_BALANCER_ENABLED", "true"),
        ("INSPACE_NODE_LOAD_BALANCER_DEFAULT_NODE_CLASS", "ci-workers"),
        ("INSPACE_NODE_LOAD_BALANCER_NODES_PER_SHARD", "1"),
    ):
        require(
            re.search(
                rf"(?m)^            - name: {re.escape(variable)}\n"
                rf"              value: \"{re.escape(value)}\"$",
                ccm_deployment,
            ) is not None,
            f"rendered CCM must set {variable}={value}",
        )

    ccm_role = manifest_document(
        rendered, "ClusterRole", "verify-inspace-cloud-kube-modules-ccm"
    )
    for api_group, resource, verbs in (
        ("karpenter.sh", "nodepools", '["get", "list", "create", "update", "delete"]'),
        ("karpenter.sh", "nodeclaims", '["get", "list"]'),
        ("karpenter.inspace.cloud", "inspacenodeclasses", '["get", "create", "update"]'),
    ):
        rule = (
            f'  - apiGroups: ["{api_group}"]\n'
            f'    resources: ["{resource}"]\n'
            f"    verbs: {verbs}"
        )
        require(rule in ccm_role,
                f"rendered CCM RBAC lacks the exact {api_group}/{resource} rule")

    disabled_result = subprocess.run(
        [*render_command, "--set", "ccm.nodeLoadBalancer.enabled=false"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )
    require(
        disabled_result.returncode == 0,
        "Helm must render with the optional CCM Node-LB controller disabled:\n"
        f"{disabled_result.stdout}{disabled_result.stderr}",
    )
    disabled_ccm_role = manifest_document(
        disabled_result.stdout, "ClusterRole", "verify-inspace-cloud-kube-modules-ccm"
    )
    require(
        'resources: ["nodepools"]' not in disabled_ccm_role
        and 'resources: ["nodeclaims"]' not in disabled_ccm_role
        and 'resources: ["inspacenodeclasses"]' not in disabled_ccm_role
        and 'resources: ["services"]\n    verbs: ["get", "list", "watch", "patch", "update"]'
        in disabled_ccm_role,
        "disabled CCM Node-LB mode must remove cloud-capacity RBAC and Service create/delete",
    )

    karpenter_deployment = manifest_document(
        rendered, "Deployment", "verify-inspace-cloud-kube-modules-karpenter"
    )
    require(
        'StaticCapacity=true' in karpenter_deployment,
        "rendered Karpenter feature gates must enable StaticCapacity",
    )

    chart_crd = (
        repository
        / "charts/inspace-cloud-kube-modules-crds/templates/karpenter.inspace.cloud_inspacenodeclasses.yaml"
    ).read_text(encoding="utf-8")
    source_crd = (
        repository
        / "modules/karpenter-provider/config/crd/bases/karpenter.inspace.cloud_inspacenodeclasses.yaml"
    ).read_text(encoding="utf-8")
    firewall_profile_schema = (
        "                firewallProfile:\n"
        "                  type: string\n"
        "                  enum: [private-worker, public-node-load-balancer]"
    )
    for name, crd in (("packaged", chart_crd), ("source", source_crd)):
        require(crd.count(firewall_profile_schema) == 1,
                f"{name} NodeClass CRD must expose the exact optional firewallProfile enum")
        required_fields = re.search(
            r"(?m)^              required:\n((?:                - [A-Za-z0-9]+\n)+)", crd
        )
        require(required_fields is not None,
                f"{name} NodeClass CRD lacks its spec required-fields block")
        require("- firewallProfile\n" not in required_fields.group(1),
                f"{name} NodeClass CRD must keep firewallProfile optional")
    require(chart_crd == source_crd,
            "packaged and source InSpaceNodeClass CRDs must remain byte-identical")

    shared_example = (chart / "examples/service-public-node-shared.yaml").read_text(encoding="utf-8")
    dedicated_example = (chart / "examples/service-public-node-dedicated.yaml").read_text(encoding="utf-8")
    shared_service = manifest_document(shared_example, "Service", "example-public-shared")
    dedicated_service = manifest_document(dedicated_example, "Service", "example-public-dedicated")
    shared_config = "\n".join(
        line for line in shared_service.splitlines()
        if not line.lstrip().startswith("#")
    )
    require("loadBalancerClass: inspace.cloud/node" in shared_config and
            "externalTrafficPolicy: Cluster" in shared_config and
            "service.inspace.cloud/node-lb-mode:" not in shared_config,
            "shared Node-LB example must exercise the omitted-mode shared default")
    require("loadBalancerClass: inspace.cloud/node" in dedicated_service and
            "externalTrafficPolicy: Cluster" in dedicated_service and
            "service.inspace.cloud/node-lb-mode: public-node-dedicated" in dedicated_service and
            'service.inspace.cloud/node-lb-cpu: "4"' in dedicated_service and
            "service.inspace.cloud/node-lb-memory: 8Gi" in dedicated_service,
            "dedicated Node-LB example must carry the mode and exact CPU/memory annotations")

    invalid_combinations = (
        ("ccm.enabled=false", "ccm.enabled must be true when ccm.nodeLoadBalancer.enabled=true"),
        ("karpenter.enabled=false", "karpenter.enabled must be true when ccm.nodeLoadBalancer.enabled=true"),
        (
            "karpenter.featureGates.staticCapacity=false",
            "karpenter.featureGates.staticCapacity must be true when ccm.nodeLoadBalancer.enabled=true",
        ),
    )
    for override, diagnostic in invalid_combinations:
        result = subprocess.run(
            [*render_command, "--set", override],
            cwd=repository,
            capture_output=True,
            text=True,
            check=False,
        )
        require(result.returncode != 0,
                f"Helm accepted inconsistent Node-LB setting {override}")
        require(diagnostic in result.stderr,
                f"Helm returned the wrong diagnostic for {override}: {result.stderr}")


def main() -> None:
    host = (ROOT / "run.sh").read_text(encoding="utf-8")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    init_playbook = (ROOT / "init-cluster.yml").read_text(encoding="utf-8")
    test_playbook = (ROOT / "test.yml").read_text(encoding="utf-8")
    cleanup = (ROOT / "destroy-cluster.yml").read_text(encoding="utf-8")
    playbook = init_playbook + "\n" + test_playbook
    entrypoint = (ROOT / "scripts/container-entrypoint.sh").read_text(encoding="utf-8")
    dockerignore = (ROOT / "Dockerfile.dockerignore").read_text(encoding="utf-8")
    account_inventory = (ROOT / "scripts/account-inventory.py").read_text(encoding="utf-8")
    cloud_audit = (ROOT / "scripts/cloud-audit.py").read_text(encoding="utf-8")
    bootstrap_discovery = (ROOT / "scripts/discover-bootstrap.py").read_text(encoding="utf-8")
    ssh_config = (ROOT / "scripts/render-ssh-config.py").read_text(encoding="utf-8")
    tunnel = (ROOT / "scripts/api-tunnel.sh").read_text(encoding="utf-8")
    worker_discovery = (ROOT / "scripts/discover-worker.py").read_text(encoding="utf-8")
    persist_workload = (ROOT / "scripts/persist-workload.py").read_text(encoding="utf-8")
    service_cloud = (ROOT / "scripts/verify-service-cloud.py").read_text(encoding="utf-8")
    node_load_balancer_cloud = (ROOT / "scripts/verify-node-load-balancer.py").read_text(encoding="utf-8")
    worker_egress = (ROOT / "scripts/ensure-worker-egress.sh").read_text(encoding="utf-8")
    nodeclass = (ROOT / "templates/karpenter.yaml.j2").read_text(encoding="utf-8")
    cluster = (ROOT / "templates/cluster.yaml.j2").read_text(encoding="utf-8")
    workload = (ROOT / "templates/workload.yaml.j2").read_text(encoding="utf-8")
    node_load_balancer_base = (ROOT / "templates/node-load-balancer.yaml.j2").read_text(encoding="utf-8")
    node_load_balancer_expansion = (
        ROOT / "templates/node-load-balancer-expansion.yaml.j2"
    ).read_text(encoding="utf-8")
    node_load_balancer_workload = node_load_balancer_base + "\n---\n" + node_load_balancer_expansion
    trigger = (ROOT / "templates/trigger.yaml.j2").read_text(encoding="utf-8")
    registry_probe = (ROOT / "templates/registry-egress-probe.yaml.j2").read_text(encoding="utf-8")
    ansible_cfg = (ROOT / "ansible.cfg").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    node_lb_service_names = (
        "inspace-e2e-node-traefik",
        "inspace-e2e-node-shared-b",
        "inspace-e2e-node-shared-conflict",
        "inspace-e2e-node-dedicated",
    )

    executable_host = "\n".join(
        line.split("#", 1)[0] for line in host.splitlines()
        if not line.lstrip().startswith("#")
    )
    verify_host_launcher_external_allow_list()
    verify_retention_state_parser(entrypoint)
    verify_worker_egress_runtime()
    verify_node_load_balancer_helm_contract()
    require("docker build" in executable_host and "docker run" in executable_host, "host launcher must build and run Docker")
    require("runner_platform=${INSPACE_E2E_RUNNER_PLATFORM:-linux/amd64}" in executable_host,
            "E2E runner must default explicitly to linux/amd64")
    require("linux/amd64 | linux/arm64" in executable_host and
            "INSPACE_E2E_RUNNER_PLATFORM must be linux/amd64 or linux/arm64" in host,
            "E2E runner platform override must reject unsupported platforms")
    require(executable_host.count('--platform "$runner_platform"') == 2,
            "E2E runner platform must be passed to both Docker build and Docker run")
    require("--target published-live" in executable_host and
            "CONTROLLER_IMAGE=ghcr.io/thanet-s/inspace-cloud-controller-manager:" in executable_host,
            "destructive launcher must copy the bootstrap binary from the exact published image")
    require("--init" not in executable_host, "host launcher must not add a second init process")
    require("--env-file" not in executable_host,
            "token-bearing environment file must not be copied into Docker container metadata")
    require("--mount \"type=bind" in host and "type=volume" in host, "host launcher must explicitly validate/mount inputs")
    require("phase=${1:-all}" in host and '"$runner_image" \\\n  "$phase"' in host,
            "host launcher must default to the full lifecycle and pass one explicit phase")
    require("interactive_arg=-it" in host and "[[ $phase == shell ]]" in host,
            "only the tunneled debug shell phase must request an interactive container")

    for tool in ("kubectl", "helm", "jq", "openssh-client", "autossh", "curl", "skopeo", "iputils-ping"):
        require(tool in dockerfile, f"runner image is missing {tool}")
    require('ENTRYPOINT ["/usr/bin/tini", "-g", "--"' in dockerfile,
            "runner must use one process-group-aware Tini")
    require("FROM base AS local-validation" in dockerfile and
            "FROM base AS published-live" in dockerfile and
            "COPY --from=published-controller /usr/local/bin/inspace-cluster-controller" in dockerfile,
            "runner must separate local validation from published live acceptance")
    for playbook_name in ("init-cluster.yml", "test.yml", "destroy-cluster.yml"):
        require(f"/opt/e2e/{playbook_name}" in dockerfile,
                f"runner image must syntax-check {playbook_name}")
    require('setsid ansible-playbook "$@" --forks 10 &' in entrypoint,
            "suite Ansible process must run in an explicitly managed process group")
    require('kill -TERM -- "-$pid"' in entrypoint and 'kill -KILL -- "-$pid"' in entrypoint and
            'kill -0 -- "-$pid"' in entrypoint,
            "signal cleanup must terminate and await the complete Ansible process group")
    require("terminate_active_ansible" in entrypoint and
            entrypoint.count("cleanup_current_run ||") >= 3,
            "signal handling must terminate the suite and route cleanup through the managed helper")
    require("ansible_starting=true" in entrypoint and
            "ansible_starting=false" in entrypoint and
            "while the Ansible process group identity was not yet stable" in entrypoint and
            "[[ $ansible_process_group_quiesced == true ]]" in entrypoint,
            "signal handling must refuse cleanup across process-group startup or quiescence uncertainty")
    require("mounted E2E environment file must have mode 0600" in entrypoint,
            "runner must reject an over-permissive API-token file")
    require("ansible-playbook autossh curl date flock" in entrypoint,
            "runner must require the UTC timestamp command before cache initialization")
    require("flock -n 9" in entrypoint and "inspace-cloud-rke2-e2e.lock" in entrypoint,
            "runner must hold one exclusive shared-state lock")
    require('value != "https://api.inspace.cloud"' in entrypoint and
            "INSPACE_API_URL must be exactly https://api.inspace.cloud" in entrypoint,
            "destructive runner must pin the exact production API origin")
    require("refusing to reuse existing E2E run ID" in entrypoint and
            "mutations-not-started" in entrypoint and
            "mutations-may-exist" in playbook and
            "missing without a mutations-not-started" in cleanup,
            "runner must journal the mutation boundary and reject run-ID reuse")
    require("[[ $retained == true ]] || ! final_audit_is_zero" in entrypoint and
            "durable retained marker" in entrypoint,
            "explicit retention must override a possibly stale zero audit")
    for forbidden_build_input in (
        "**/.env", "**/*.env", "**/id_rsa", "**/id_ed25519", "**/*.pem", "**/*.key",
        "**/__pycache__", "**/*.py[cod]",
    ):
        require(forbidden_build_input in dockerignore,
                f"Dockerfile-specific ignore is missing {forbidden_build_input}")
    require("INSPACE_CONTROL_PLANE_VIP" in entrypoint,
            "runner must require the private control-plane VIP before provisioning")
    require("INSPACE_AMD_HOST_POOL_UUID" in entrypoint and
            "INSPACE_AMD_HOST_POOL_UUID" in cluster and
            "INSPACE_AMD_HOST_POOL_UUID" in bootstrap_discovery,
            "runner, bootstrap template, and readback must require the AMD EPYC pool")
    require("INSPACE_INTEL_HOST_POOL_UUID" not in entrypoint and
            "INSPACE_INTEL_HOST_POOL_UUID" not in cluster and
            "INSPACE_INTEL_HOST_POOL_UUID" not in bootstrap_discovery,
            "live cluster E2E must not retain an Intel pool input")
    for variable in (
        "INSPACE_PRIVATE_LOAD_BALANCER_POOL_START",
        "INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP",
    ):
        require(variable in entrypoint, f"runner must require {variable}")
        require(variable in cluster, f"cluster template must render {variable}")
        require(variable in nodeclass, f"NodeClass template must render {variable}")
    require("16 <= int(stop)-int(start)+1 <= 256" in playbook,
            "live preflight must enforce the v1alpha1 16-256-address pool bound")
    require("recovering unfinished E2E run" in entrypoint and
            "cleanup lacks a final zero audit" in entrypoint and
            "requires INSPACE_E2E_VERSION=" in entrypoint and
            "INSPACE_E2E_RECOVER_RETAINED" in entrypoint,
            "runner must recover unfinished state without deleting explicitly retained resources")
    for phase_call in (
        "run_ansible /opt/e2e/init-cluster.yml",
        "run_ansible /opt/e2e/test.yml",
        "run_ansible /opt/e2e/destroy-cluster.yml",
        "run_ansible /opt/e2e/test.yml --tags e2e-attach",
    ):
        require(phase_call in entrypoint, f"phase-aware entrypoint is missing {phase_call}")
    require("cluster preserved for debugging or explicit destroy" in entrypoint and
            "cluster $E2E_RUN_ID preserved after test phase" in entrypoint and
            "Tunneled kubectl shell" in entrypoint,
            "init, test, and shell phases must preserve a reusable cluster")
    require("mark_phase_preserved" in entrypoint and
            "$previous_dir/phase-preserved" in entrypoint and
            "preserved by the phased workflow" in entrypoint and
            "clear_phase_preserved" in entrypoint,
            "phased clusters must require explicit destroy instead of implicit all-mode recovery")
    require("select_debuggable_run" in entrypoint and
            "e2e_attach_require_initialized=false" in entrypoint and
            "Normalize the persisted kubeconfig for the container-local tunnel" in test_playbook,
            "the shell must support access-facts-gated debugging after a late init failure")
    require("initComplete" in init_playbook and "testComplete" in test_playbook and
            "Attach to an initialized RKE2 E2E cluster" in test_playbook and
            "Heal state left by an interrupted acceptance run" in test_playbook,
            "split phases must journal initialization and make acceptance re-attachable")
    require("ansible-core==" in (ROOT / "requirements.txt").read_text(), "ansible-core must be pinned")
    require(re.search(r"^forks\s*=\s*(?:[3-9]|[1-9][0-9]+)$", ansible_cfg, re.MULTILINE) is not None,
            "Ansible forks must be at least three")
    require(re.search(r"^task_timeout\s*=\s*(?:2[1-9][0-9]{2}|[3-9][0-9]{3,})$", ansible_cfg, re.MULTILINE) is not None,
            "every Ansible action must have a hard timeout of at least 2100 seconds")

    # Exact-path scanning is only authoritative when template control flow cannot
    # hide the replicas field at render time. Value expressions remain allowed.
    require("{%" not in cluster and "{#" not in cluster,
            "cluster template must not contain Jinja control flow or template comments")
    require(yaml_mapping_scalar(cluster, "spec", "controlPlane", "replicas") == "3",
            "cluster template spec.controlPlane.replicas must be exactly 3")
    require(yaml_mapping_scalar(cluster, "spec", "bootstrapCache", "directDownload") == "false",
            "cluster template must enable the default bastion cache explicitly")
    require(yaml_mapping_scalar(cluster, "spec", "rke2", "skipOSUpgrade") == "true",
            "guarded E2E bootstrap must explicitly skip only the full OS upgrade")
    for marker in (
        'e2e_bootstrap_cache_key_file: "{{ lookup(\'env\', \'E2E_STATE_DIR\') }}/bootstrap-cache-key"',
        "Generate the 256-bit bootstrap cache key inside the runner",
        'argv: [openssl, rand, -hex, "32"]',
        "lookup('file', e2e_bootstrap_cache_key_file) is match('^[0-9a-f]{64}$')",
        'e2e_bootstrap_cache_not_before_file: "{{ lookup(\'env\', \'E2E_STATE_DIR\') }}/bootstrap-cache-not-before"',
        "Capture the bootstrap cache certificate epoch at cluster initialization",
        'argv: [date, -u, "+%Y-%m-%dT%H:%M:%SZ"]',
        "Require an exact persisted UTC bootstrap cache certificate epoch",
        "Prove the cache CA is ECDSA P-256 with exactly fifteen years from the persisted epoch",
        "Public Key Algorithm: id-ecPublicKey",
        "ASN1 OID: prime256v1",
        "expected.replace(year=expected.year + 15)",
    ):
        require(marker in init_playbook, f"cached bootstrap initialization is missing: {marker}")
    provision_play = named_yaml_sequence_item(
        playbook, "Provision the RKE2 control plane through the product bootstrap controller", 0
    )
    require_yaml_key(provision_play, 2, "hosts", "localhost")
    require("api.ipify.org" not in provision_play and
            'e2e_management_cidr: "{{ lookup(\'env\', \'INSPACE_MANAGEMENT_CIDR\') | default(\'0.0.0.0/0\', true) }}"' in provision_play,
            "bootstrap must default bastion management to Any without public-IP discovery")
    launch_task = named_yaml_sequence_item(provision_play, "Run the bootstrap reconciler synchronously to readiness", 4)
    require("\n      ansible.builtin.command:" in launch_task,
            "bootstrap launch task must use ansible.builtin.command")
    require(
        yaml_scalar_sequence(launch_task, 8, "argv") == [
            "inspace-cluster-controller",
            "--cluster-config",
            '"{{ e2e_cluster_file }}"',
            "--ssh-public-key-file",
            '"{{ lookup(\'env\', \'E2E_PUBLIC_KEY\') }}"',
            "--ssh-username",
            '"{{ e2e_ssh_user }}"',
            "--management-cidr",
            '"{{ e2e_management_cidr }}"',
            "--management-tcp-ports",
            '"22"',
            "--until-ready",
            "--interval",
            "15s",
            "--output=json",
        ],
        "bootstrap launch argv must be the canonical until-ready controller invocation",
    )
    require_yaml_key(launch_task, 6, "register", "e2e_bootstrap_wait")
    require('INSPACE_BOOTSTRAP_CACHE_KEY: "{{ lookup(\'file\', e2e_bootstrap_cache_key_file) | trim }}"' in launch_task and
            'INSPACE_BOOTSTRAP_CACHE_NOT_BEFORE: "{{ lookup(\'file\', e2e_bootstrap_cache_not_before_file) | trim }}"' in launch_task,
            "cached bootstrap launch must receive its persisted key and certificate epoch")
    require("\n      async:" not in launch_task and "ansible.builtin.async_status" not in provision_play,
            "bootstrap cloud mutation must remain attached to the managed Ansible process group")
    parallel_assertion = named_yaml_sequence_item(
        provision_play, "Prove exact and parallel three-control-plane provisioning", 4
    )
    for clause in (
        "e2e_bootstrap_result.controlPlaneVMs | length == 3",
        "e2e_bootstrap_result.controlPlaneVMs | unique | length == 3",
        "e2e_bootstrap_result.maxParallelControlPlaneCreates | int == 3",
        "e2e_bootstrap_result.bootstrapCacheEndpoint == 'https://cache.' + e2e_cluster_name + '.inspace.internal:8443'",
        "e2e_bootstrap_result.bootstrapCacheRegistry == 'cache.' + e2e_cluster_name + '.inspace.internal:8443'",
        "e2e_bootstrap_result.bootstrapCacheAddress == e2e_bootstrap_result.bastionPrivateIPv4",
        "e2e_bootstrap_result.bootstrapCacheCABundle is match('^-----BEGIN CERTIFICATE-----\\n')",
    ):
        require(f"\n          - {clause}" in parallel_assertion,
                f"parallel provisioning assertion lacks exact clause: {clause}")
    authoritative_parallel_binding = named_yaml_sequence_item(
        provision_play, "Bind the parallel-create contract to the authoritative three VM identities", 4
    )
    for clause in (
        "e2e_state.controlPlanes | length == 3",
        "e2e_state.controlPlanes | map(attribute='uuid') | list | unique | length == 3",
        "e2e_state.controlPlanes | map(attribute='uuid') | list | difference(e2e_bootstrap_result.controlPlaneVMs) | length == 0",
        "e2e_bootstrap_result.controlPlaneVMs | difference(e2e_state.controlPlanes | map(attribute='uuid') | list) | length == 0",
        "(e2e_bootstrap_result.maxParallelControlPlaneCreates | int) == (e2e_state.controlPlanes | length)",
    ):
        require(f"\n          - {clause}" in authoritative_parallel_binding,
                f"authoritative parallel-create binding lacks exact clause: {clause}")

    control_plane_wait_play = named_yaml_sequence_item(
        playbook, "Wait for all RKE2 servers independently and in parallel through the bastion", 0
    )
    require_yaml_key(control_plane_wait_play, 2, "hosts", "rke2_control_plane")
    require_yaml_key(control_plane_wait_play, 2, "strategy", "free")
    require_yaml_key(control_plane_wait_play, 2, "any_errors_fatal", "true")
    require(re.search(r"(?m)^  serial:", control_plane_wait_play) is None,
            "parallel control-plane wait play must not set serial")
    private_ssh_probe = named_yaml_sequence_item(
        control_plane_wait_play, "Probe every private control-plane SSH port from the bastion in parallel", 4
    )
    require("\n      ansible.builtin.command:" in private_ssh_probe,
            "private control-plane SSH probe must be a command task")
    require_unrestricted_parallel_task(private_ssh_probe)
    require_yaml_key(private_ssh_probe, 6, "retries", "120")
    require_yaml_key(private_ssh_probe, 6, "delay", "5")
    require_yaml_key(private_ssh_probe, 6, "until", "e2e_private_ssh_probe.rc == 0")
    host_key_wait = named_yaml_sequence_item(
        control_plane_wait_play, "Scan each private control-plane host key from the bastion", 4
    )
    require_unrestricted_parallel_task(host_key_wait)
    require_yaml_key(host_key_wait, 6, "retries", "20")
    require_yaml_key(host_key_wait, 6, "delay", "5")
    require_yaml_key(
        host_key_wait, 6, "until", "e2e_host_keyscan.rc == 0 and e2e_host_keyscan.stdout | length > 0"
    )
    connection_wait = named_yaml_sequence_item(
        control_plane_wait_play, "Wait for authenticated SSH on every control plane in parallel", 4
    )
    require_unrestricted_parallel_task(connection_wait)
    require("\n      ansible.builtin.wait_for_connection:" in connection_wait,
            "control-plane authenticated SSH wait must use wait_for_connection")
    require_yaml_key(connection_wait, 8, "connect_timeout", "10")
    require_yaml_key(connection_wait, 8, "sleep", "5")
    require_yaml_key(connection_wait, 8, "timeout", "1200")
    cloud_init_wait = named_yaml_sequence_item(
        control_plane_wait_play, "Wait for cloud-init completion on every control plane in parallel", 4
    )
    require_unrestricted_parallel_task(cloud_init_wait)
    require("\n      ansible.builtin.raw: >-" in cloud_init_wait and
            "timeout --kill-after=5s 4800s sh -c" in cloud_init_wait,
            "control-plane cloud-init wait must cover bounded cold-cache initialization inside the free-strategy play")
    product_preparation = named_yaml_sequence_item(
        control_plane_wait_play, "Detect completed product node preparation on every control plane", 4
    )
    require("ansible.builtin.stat:" in product_preparation and
            "path: /var/lib/inspace/kubernetes-node-prepared-v1" in product_preparation,
            "Ansible node preparation must detect the product bootstrap checkpoint")
    persistent_swap = named_yaml_sequence_item(
        control_plane_wait_play, "Disable persistent swap entries on every control plane in parallel", 4
    )
    require("ansible.builtin.replace:" in persistent_swap and
            r"regexp: '^(?!\s*#)(.*\s+swap\s+.*)$'" in persistent_swap and
            "when: not e2e_node_preparation.stat.exists" in persistent_swap,
            "persistent swap removal must use the exact idempotent Python regexp and checkpoint guard")
    mirror_selection = named_yaml_sequence_item(
        control_plane_wait_play, "Configure ordered TOT and KKU Ubuntu mirrors on every control plane in parallel", 4
    )
    require("dest: /etc/apt/mirrors/inspace-ubuntu.list" in mirror_selection and
            'http://mirror1.totbb.net/ubuntu/{{ "\\t" }}priority:1' in mirror_selection and
            'https://mirror.kku.ac.th/ubuntu/{{ "\\t" }}priority:2' in mirror_selection,
            "Ansible node preparation must configure the ordered TOT and KKU mirror list")
    ubuntu_sources = named_yaml_sequence_item(
        control_plane_wait_play, "Configure Ubuntu update and security suites on every control plane in parallel", 4
    )
    require("dest: /etc/apt/sources.list.d/ubuntu.sources" in ubuntu_sources and
            ubuntu_sources.count("URIs: mirror+file:/etc/apt/mirrors/inspace-ubuntu.list") == 2 and
            "Suites: noble-security" in ubuntu_sources,
            "Ansible node preparation must use the ordered mirror list for update and security suites")
    require(init_playbook.count("test ! -s /etc/apt/sources.list") == 2 and
            "test ! -e /etc/apt/sources.list" not in init_playbook,
            "control-plane and worker acceptance must allow only an absent or empty legacy sources.list")
    static_dns = named_yaml_sequence_item(
        control_plane_wait_play, "Configure static Google DNS on every control plane in parallel", 4
    )
    require("dest: /etc/resolv.conf" in static_dns and "nameserver 8.8.8.8" in static_dns and
            "nameserver 8.8.4.4" in static_dns,
            "Ansible node preparation must install the static Google resolver")
    disable_resolved = named_yaml_sequence_item(
        control_plane_wait_play, "Disable systemd-resolved on every control plane in parallel", 4
    )
    require("ansible.builtin.systemd_service:" in disable_resolved and
            "name: systemd-resolved.service" in disable_resolved and "masked: true" in disable_resolved,
            "Ansible node preparation must stop and mask systemd-resolved")
    package_refresh = named_yaml_sequence_item(
        control_plane_wait_play, "Refresh package indexes without upgrading repaired E2E control planes", 4
    )
    require("update_cache: true" in package_refresh and "upgrade:" not in package_refresh and
            "NEEDRESTART_MODE: l" in package_refresh and
            "async: 600" in package_refresh and "poll: 10" in package_refresh and
            "when: not e2e_node_preparation.stat.exists" in package_refresh,
            "E2E repair must refresh indexes without restoring the skipped full OS upgrade")
    repaired_restart = named_yaml_sequence_item(
        control_plane_wait_play, "Restart repaired RKE2 servers one at a time and prove local readiness", 4
    )
    require("throttle: 1" in repaired_restart and "systemctl restart --no-block rke2-server.service" in repaired_restart and
            "old_pid=$(systemctl show rke2-server.service --property=MainPID --value)" in repaired_restart and
            'test "$new_pid" != "$old_pid"' in repaired_restart and
            "restart_deadline=$(( $(date +%s) + 1200 ))" in repaired_restart and "timeout 10s" in repaired_restart and
            "[+]etcd ok" in repaired_restart and '"$attempt" -ge 180' in repaired_restart and
            "sysctl -n net.ipv4.ip_forward" in repaired_restart and "LimitNOFILE" in repaired_restart,
            "repaired control planes must restart serially and prove bounded local etcd and tuning readiness")
    for marker in (
        "Persist Kubernetes sysctls on repaired control planes",
        "dest: /etc/sysctl.d/90-inspace-kubernetes.conf",
        "Persist Kubernetes PAM limits on repaired control planes",
        "dest: /etc/security/limits.d/90-inspace-kubernetes.conf",
        "Create the repaired RKE2 server drop-in directory",
        "path: /etc/systemd/system/rke2-server.service.d",
        "state: directory",
        "Persist RKE2 server limits on repaired control planes",
        "dest: /etc/systemd/system/rke2-server.service.d/20-inspace-node-limits.conf",
        "Apply Kubernetes sysctls on repaired control planes",
        "Persist completed repaired node preparation",
    ):
        require(marker in control_plane_wait_play,
                f"repaired control-plane convergence is missing: {marker}")
    rke2_wait = named_yaml_sequence_item(
        control_plane_wait_play, "Wait for every rke2-server service in parallel", 4
    )
    require_unrestricted_parallel_task(rke2_wait)
    require_yaml_key(rke2_wait, 6, "retries", "180")
    require_yaml_key(rke2_wait, 6, "delay", "10")
    require_yaml_key(
        rke2_wait, 6, "until", "e2e_rke2_service.rc == 0 and e2e_rke2_service.stdout == 'active'"
    )
    readyz_wait = named_yaml_sequence_item(
        control_plane_wait_play, "Wait for embedded etcd and the local API on every server in parallel", 4
    )
    require_unrestricted_parallel_task(readyz_wait)
    require_yaml_key(readyz_wait, 6, "retries", "120")
    require_yaml_key(readyz_wait, 6, "delay", "10")
    require_yaml_key(readyz_wait, 6, "until", "e2e_local_readyz.rc == 0")
    control_plane_contract = named_yaml_sequence_item(
        control_plane_wait_play, "Verify pinned RKE2 and Ubuntu versions on every control plane", 4
    )
    for marker in (
        '# inspace-bootstrap-cache" /etc/hosts',
        'system-default-registry: \\"$cache_registry\\"',
        "cmp -s - /etc/rancher/rke2/bootstrap-cache-ca.crt",
        "/etc/rancher/rke2/registries.yaml",
        "kube_vip_manifest=/var/lib/rancher/rke2/agent/pod-manifests/kube-vip.yaml",
        "$cache_registry/kube-vip/kube-vip:v1.2.1@sha256:44035f68040c9eb99103c65f1f9ab9698d93f9f272110825705338ac1926f3d9",
        "! grep -Fq 'ghcr.io/kube-vip/' \"$kube_vip_manifest\"",
        "grep -Fc '    - ip: \"127.0.0.1\"'",
        "grep -Fc '        - \"kubernetes\"'",
        "grep -Fc '        - name: vip_nodename'",
        "grep -Fc '              fieldPath: spec.nodeName'",
        "grep -Fc '          drop: [\"ALL\"]'",
        "grep -Fc '          add: [\"NET_ADMIN\", \"NET_RAW\"]'",
        "grep -Fc '          mountPath: /etc/kubernetes/admin.conf'",
        "grep -Fc '        path: /etc/rancher/rke2/rke2.yaml'",
        "! grep -Fq 'k8s_config_file' \"$kube_vip_manifest\"",
    ):
        require(marker in control_plane_contract,
                f"per-node kube-vip manifest proof is missing: {marker}")

    for marker in (
        "maxParallelControlPlaneCreates | int == 3",
        "e2e_bootstrap_result.apiLoadBalancerUUID is not defined",
        "e2e_bootstrap_result.bastionVMUUID | length > 0",
        "controlPlaneVMs | length == 3",
        "groups: rke2_control_plane",
        "groups: rke2_bastion",
        "strategy: free",
        "Run the bootstrap reconciler synchronously to readiness",
        "wait_for_connection",
        "systemctl is-active rke2-server",
        "timeout --kill-after=5s 1200s sh -c",
        "KubeProxyReplacement:[[:space:]]+True",
        "Direct Routing",
        "auto-direct-node-routes",
        "enable-bpf-masquerade",
        "enable-l2-announcements",
        "default-lb-service-ipam",
        "defaultLBServiceIPAM:[[:space:]]*none",
        "nodeIPAM:[[:space:]]*$",
        "ciliumloadbalancerippool inspace-private",
        "ciliuml2announcementpolicy inspace-private",
        "EnableL2Announcements",
        "inspace-control-plane-vip",
        "/var/lib/inspace/kube-vip.yaml.e2e-disabled",
        "Require uninterrupted API reachability during kube-vip failover",
        "Prove the chart launched the exact released product image tags",
        "/opt/e2e/scripts/api-tunnel.sh",
        "skopeo",
        "global.inspace.privateLoadBalancerPool.start",
        "global.inspace.privateLoadBalancerPool.stop",
        "global.inspace.controlPlaneVIP",
        "global.inspace.systemImageRegistry",
        "Require the persisted default bootstrap cache contract",
        "Recheck the private bastion cache by its stable TLS hostname",
        "Verify Cilium native routing and full kube-proxy replacement",
        "Masquerading:[[:space:]]+BPF",
        "EnableBPFMasquerade",
        "EnableIPv4Masquerade",
        "exec_cilium",
        "cilium_exec_attempt=$((cilium_exec_attempt + 1))",
        '"$cilium_exec_attempt" -ge 5',
        "10\\.42\\.0\\.0/16",
        "Disable active swap on every control plane in parallel",
        "Disable persistent swap entries on every control plane in parallel",
        "Configure ordered TOT and KKU Ubuntu mirrors on every control plane in parallel",
        "Configure Ubuntu update and security suites on every control plane in parallel",
        "Configure static Google DNS on every control plane in parallel",
        "Disable systemd-resolved on every control plane in parallel",
        "Refresh package indexes without upgrading repaired E2E control planes",
        "/etc/apt/apt.conf.d/99-inspace-disable-periodic",
        'APT::Periodic::Unattended-Upgrade "0";',
        "/etc/sysctl.d/90-inspace-kubernetes.conf",
        "/etc/security/limits.d/90-inspace-kubernetes.conf",
        "LimitMEMLOCK",
    ):
        require(marker in playbook, f"playbook is missing contract marker: {marker}")

    require("version: v1.35.6+rke2r1" in cluster, "control plane must pin supported RKE2")
    require("rootDiskGiB: 60" in cluster, "E2E control planes must use 60 GiB root disks")
    require("rke2-ingress-nginx" in cluster, "unused RKE2 ingress must be disabled")
    require("virtualIPv4:" in cluster and "public:" not in cluster and "host:" not in cluster,
            "cluster endpoint must be only the configured private VIP")
    require("routing-mode" in playbook and "kube-proxy-replacement" in playbook,
            "native routing and kube-proxy replacement must be verified")
    require("rke2:" in nodeclass and "privateRegistrationEndpoint" in nodeclass,
            "NodeClass must use the private RKE2 registration endpoint")
    require(yaml_mapping_scalar(nodeclass, "spec", "rke2", "skipOSUpgrade") == "true",
            "guarded E2E NodeClass must explicitly skip only the full OS upgrade")
    require("inspace-rke2-agent-token" in nodeclass, "NodeClass must use the RKE2 token secret")
    require("rootDiskGiB: 100" in nodeclass, "E2E Karpenter workers must use 100 GiB root disks")
    require('limits:\n    cpu: "8"\n    memory: 16Gi' in nodeclass,
            "E2E NodePool must retain bounded headroom for scale-out experiments")
    require("bootstrapCache:" in nodeclass and
            "directDownload: false" in nodeclass and
            'address: "{{ e2e_bootstrap_result.bootstrapCacheAddress }}"' in nodeclass and
            "caBundle: {{ e2e_bootstrap_result.bootstrapCacheCABundle | to_json }}" in nodeclass,
            "E2E NodeClass must consume the reconciler's bastion address and public cache CA")
    require("hostPoolSelector" not in nodeclass and
            "key: inspace.cloud/host-class" in nodeclass and
            "values: [amd-epyc]" in nodeclass and
            "intel-scalable" not in nodeclass,
            "E2E NodePool must exclusively select AMD EPYC workers")
    require(nodeclass.count("""        - key: inspace.cloud/instance-family
          operator: In
          values: [general]""") == 1 and
            nodeclass.count("""        - key: inspace.cloud/instance-cpu
          operator: Gt
          values: ["1"]""") == 1 and
            "key: inspace.cloud/instance-memory" not in nodeclass,
            "E2E general NodePool must require CPU Gt 1 without an instance-memory selector")
    require('(.spec | has("hostPoolSelector") | not)' in playbook and
            ".status.hostPoolUUIDs | sort" in playbook and
            '.key == "inspace.cloud/instance-family"' in playbook and
            '.values == ["general"]' in playbook and
            '.key == "inspace.cloud/instance-cpu"' in playbook and
            '.operator == "Gt"' in playbook and
            '.values == ["1"]' in playbook and
            '.key == "inspace.cloud/host-class"' in playbook and
            ".spec.rke2.skipOSUpgrade == true" in playbook and
            'all($requirements[]; .key != "inspace.cloud/instance-memory")' in playbook and
            "INSPACE_AMD_HOST_POOL_UUID" in playbook,
            "live NodeClass and NodePool checks must prove the unpinned-memory AMD general Gt 1 selection")
    require('(.spec.bootstrapCache | keys | sort) == ["address", "caBundle", "directDownload"]' in playbook and
            ".spec.bootstrapCache.directDownload == false" in playbook and
            ".spec.bootstrapCache.address == $cacheAddress" in init_playbook and
            ".spec.bootstrapCache.caBundle == $cacheCA" in init_playbook,
            "live NodeClass acceptance must prove the complete cached-mode contract")
    require(init_playbook.count("! grep -Fq 'upgrade -y'") == 3 and
            "/usr/local/sbin/inspace-bootstrap-cache-bastion" in init_playbook and
            "/usr/local/sbin/inspace-bootstrap-rke2" in init_playbook and
            "/usr/local/sbin/inspace-install-prerequisites" in init_playbook,
            "live bootstrap acceptance must prove the E2E upgrade bypass on bastion, control planes, and workers")
    require('"global.inspace.systemImageRegistry={{ e2e_state.bootstrapCacheRegistry }}"' in init_playbook and
            '"$registry/thanet-s/inspace-cloud-controller-manager:$version"' in init_playbook and
            '"$registry/sig-storage/csi-provisioner:v5.2.0"' in init_playbook,
            "released chart installation must route its audited system images through the cache")
    cached_pause = "rancher/mirrored-pause:3.6@sha256:c2280d2f5f56cf9c9a01bb64b2db4651e35efd6d62a54dcfc12049fe6449c5e4"
    require(f"image: {{{{ e2e_state.bootstrapCacheRegistry }}}}/{cached_pause}" in trigger and
            playbook.count(cached_pause) == 2,
            "the Karpenter capacity trigger must use the audited node-bootstrap pause image")
    docker_busybox = "docker.io/library/busybox:1.36.1@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f"
    docker_nginx = "docker.io/library/nginx:1.27.5-alpine@sha256:62223d644fa234c3a1cc785ee14242ec47a77364226f1c811d2f669f96dc2ac8"
    ghcr_busybox = "ghcr.io/containerd/busybox:latest@sha256:febcf61cd6e1ac9628f6ac14fa40836d16f3c6ddef3b303ff0321606e55ddd0b"
    require(f"image: {docker_busybox}" in workload and
            workload.count(f"image: {docker_nginx}") == 3 and
            "public.ecr.aws" not in workload and
            "bootstrapCacheRegistry" not in workload,
            "acceptance workloads must use direct digest-pinned Docker Hub images")
    require(registry_probe.count(f"image: {docker_busybox}") == 2 and
            registry_probe.count(f"image: {ghcr_busybox}") == 1 and
            registry_probe.count("imagePullPolicy: Always") == 2 and
            'inspace.cloud/e2e-egress-gate: "true"' in registry_probe and
            'karpenter.sh/do-not-disrupt: "true"' in registry_probe and
            "nginx" not in registry_probe and
            "bootstrapCacheRegistry" not in registry_probe,
            "the worker gate must pull tiny immutable Docker Hub and GHCR blobs directly")
    egress_gate_call = init_playbook.index("- name: Replace only registry-timeout workers while retaining their FIPs")
    worker_identity_read = init_playbook.index("- name: Read the exact Karpenter worker identity")
    require(egress_gate_call < worker_identity_read and
            "/opt/e2e/scripts/ensure-worker-egress.sh" in init_playbook[egress_gate_call:worker_identity_read] and
            "worker-egress.json" in init_playbook[egress_gate_call:worker_identity_read],
            "the blue/green egress gate must finish before persisting one final worker identity")
    winner_check = worker_egress.index('[[ -n "$winner_node" ]]')
    old_claim_delete = worker_egress.index("delete nodeclaim")
    restore_limit = worker_egress.index('"cpu\\":\\"$original_cpu')
    require("readonly max_attempts=3" in worker_egress and
            "readonly pull_timeout=5m" in worker_egress and
            '"cpu\\":\\"$surge_cpu' in worker_egress and
            '"memory\\":\\"$surge_memory' in worker_egress and
            '[[ "$public_ip" != "${rejected_ips[$index]}" ]]' in worker_egress and
            worker_egress.count("reprove_rejected") >= 3 and
            "refusing pointless FIP rotation" in worker_egress and
            "refusing speculative FIP rotation" in worker_egress and
            "i/o timeout|tls handshake timeout" in worker_egress and
            "trap cleanup EXIT" in worker_egress and
            "trap 'exit 130' INT" in worker_egress and
            "trap 'exit 143' TERM" in worker_egress and
            winner_check < old_claim_delete < restore_limit,
            "worker replacement must be bounded, timeout-only, overlapping, and delete old FIPs only after a winner")
    require("Delete transient registry-egress gate pods before worker teardown" in cleanup and
            cleanup.count("inspace.cloud/e2e-egress-gate=true") >= 2,
            "destroy must remove retained egress probes before deleting the NodePool")
    require(playbook.count('.metadata.labels["inspace.cloud/host-class"] == "amd-epyc"') >= 2 and
            playbook.count('.metadata.labels["inspace.cloud/instance-cpu"] == "2"') >= 2 and
            playbook.count('.metadata.labels["inspace.cloud/instance-memory"] == "4096"') >= 2,
            "live worker checks must prove resolved host-class and numeric capacity labels")
    public_recheck = playbook.index("- name: Recheck the public TCP NLB after pod replacement")
    public_delete = playbook.index("- name: Delete only the paid public Service after its acceptance checks")
    suite_complete = playbook.index("- name: Mark the full RKE2 CCM CSI Karpenter acceptance suite complete")
    cleanup_window = playbook[public_delete:suite_complete]
    require(public_recheck < public_delete < suite_complete and
            "service/inspace-e2e-web" in cleanup_window and
            "--wait=false" in cleanup_window and
            "--ignore-not-found -o name" in cleanup_window and
            "service/inspace-e2e-private-a" in cleanup_window and
            "service/inspace-e2e-private-b" in cleanup_window and
            "deployment/inspace-e2e-web" in cleanup_window and
            "deployment/inspace-e2e-private-a" in cleanup_window and
            "deployment/inspace-e2e-private-b" in cleanup_window and
            "deployment/inspace-e2e-trigger" in cleanup_window and
            "pvc/inspace-e2e-rwo" in cleanup_window and
            "--state \"{{ e2e_state_file }}\"" in cleanup_window and
            "--immutable-baseline \"{{ e2e_baseline_inventory_file }}\"" in cleanup_window and
            "--public absent" in cleanup_window,
            "live acceptance must delete only the paid public Service, prove cloud cleanup, and preserve every other workload")
    node_lb_baseline = playbook.index("- name: Capture the exact account inventory before Node-LB acceptance")
    stale_paid_service_absent = playbook.index("- name: Wait for the stale paid public Service owner to disappear")
    stale_paid_nlb_inventory = playbook.index(
        "- name: Require stale paid NLB inventory to return to the immutable account baseline"
    )
    node_lb_stale_absent = playbook.index("- name: Wait for stale Node-LB cloud and Kubernetes owners to quiesce")
    node_lb_immutable_anchor = playbook.index("- name: Require the immutable zero-NLB anchor before Node-LB baseline capture")
    node_lb_exercise_start = playbook.index("- name: Exercise shared conflict and dedicated public Node-LB modes")
    node_lb_initial_apply = playbook.index("- name: Create the Node-LB workload and established shared pair")
    node_lb_initial_journal = playbook.index("- name: Journal initial Node-LB identities before cloud convergence")
    node_lb_shared_pair = playbook.index(
        "- name: Require the mixed Traefik and sibling Services to establish one shared shadow shard"
    )
    node_lb_expansion = playbook.index("- name: Add the conflicting shared and dedicated Node-LB Services")
    node_lb_full_journal = playbook.index("- name: Journal every Node-LB identity before the full convergence proof")
    node_lb_present = playbook.index("- name: Prove Node-LB Kubernetes cloud and ownership convergence")
    node_lb_http = playbook.index("- name: Prove every public Node-LB TCP port reaches its exact backend")
    node_lb_partial_delete = playbook.index("- name: Delete one shared Node-LB member without deleting its sibling shard")
    node_lb_partial = playbook.index("- name: Prove partial shared-member cleanup preserves the exact sibling resources")
    node_lb_partial_identity_assert = playbook.index(
        "- name: Assert the exact surviving Service firewall identity after partial cleanup"
    )
    node_lb_partial_http = playbook.index("- name: Prove the retained mixed and other TCP backends after partial cleanup")
    node_lb_delete = playbook.index("- name: Delete every Node-LB acceptance Service and workload owner")
    node_lb_absent = playbook.index("- name: Require Node-LB Services shadows NodePools firewalls VMs and FIPs to disappear")
    require(stale_paid_service_absent < stale_paid_nlb_inventory < node_lb_stale_absent < public_delete < node_lb_immutable_anchor < node_lb_baseline < node_lb_exercise_start <
            node_lb_initial_apply < node_lb_initial_journal < node_lb_shared_pair <
            node_lb_expansion < node_lb_full_journal < node_lb_present < node_lb_http < node_lb_partial_delete <
            node_lb_partial < node_lb_partial_identity_assert < node_lb_partial_http < node_lb_delete <
            node_lb_absent < suite_complete,
            "Node-LB acceptance must run after paid-NLB cleanup and finish before suite completion")
    stale_paid_nlb_task = named_yaml_sequence_item(
        test_playbook,
        "Require stale paid NLB inventory to return to the immutable account baseline",
        4,
    )
    stale_node_lb_task = named_yaml_sequence_item(
        test_playbook, "Wait for stale Node-LB cloud and Kubernetes owners to quiesce", 4
    )
    immutable_node_lb_anchor_task = named_yaml_sequence_item(
        test_playbook, "Require the immutable zero-NLB anchor before Node-LB baseline capture", 4
    )
    for task_name, task in (
        ("stale paid NLB", stale_paid_nlb_task),
        ("stale Node-LB", stale_node_lb_task),
        ("pre-Node-LB anchor", immutable_node_lb_anchor_task),
    ):
        require(
            "--immutable-baseline" in task
            and '"{{ e2e_baseline_inventory_file }}"' in task,
            f"{task_name} cleanup proof must use the immutable pre-mutation NLB UUID baseline",
        )
    require(
        "--public\n          - absent" in stale_paid_nlb_task
        and "service/inspace-e2e-web" in named_yaml_sequence_item(
            test_playbook, "Remove stale paid and Node-LB acceptance owners", 4
        )
        and "--immutable-baseline" in cleanup
        and '"{{ e2e_baseline_inventory_file }}"' in cleanup,
        "every absent Node-LB proof must use the immutable pre-mutation NLB UUID baseline",
    )
    node_lb_exercise = named_yaml_sequence_item(
        test_playbook, "Exercise shared conflict and dedicated public Node-LB modes", 4
    )
    final_node_lb_absent_task = named_yaml_sequence_item(
        node_lb_exercise,
        "Require Node-LB Services shadows NodePools firewalls VMs and FIPs to disappear",
        8,
    )
    require(
        "--immutable-baseline" in final_node_lb_absent_task
        and '"{{ e2e_baseline_inventory_file }}"' in final_node_lb_absent_task,
        "final Node-LB absence proof must use the immutable pre-mutation NLB UUID baseline",
    )
    require("\n      always:\n" in node_lb_exercise and
            node_lb_exercise.count("/opt/e2e/scripts/verify-node-load-balancer.py") == 3 and
            "--expect\n              - present" in node_lb_exercise and
            "--expect\n              - partial" in node_lb_exercise and
            "--expect\n              - absent" in node_lb_exercise and
            "/opt/e2e/scripts/account-inventory.py" in node_lb_exercise and
            "compare" in node_lb_exercise and
            "--baseline" in node_lb_exercise and
            "Require the mixed Traefik and sibling Services to establish one shared shadow shard" in node_lb_exercise and
            '"io.cilium.nodeipam/match-node-labels"' in node_lb_exercise and
            '"inspace.cloud/node-lb-service-uid"' in node_lb_exercise and
            "Add the conflicting shared and dedicated Node-LB Services" in node_lb_exercise and
            "--deleted-firewall" in node_lb_exercise and
            "--retained-icmp-firewall" in node_lb_exercise and
            "--retained-service-firewall" in node_lb_exercise and
            "service/inspace-e2e-node-shared-b" in node_lb_exercise and
            node_lb_exercise.count("/opt/e2e/scripts/persist-workload.py") == 2 and
            "e2e_node_lb_expansion_manifest" in node_lb_exercise and
            "use_proxy: false" in node_lb_exercise,
            "Node-LB live acceptance must prove presence/data path and always restore exact inventory")
    node_lb_partial_task = named_yaml_sequence_item(
        node_lb_exercise,
        "Prove partial shared-member cleanup preserves the exact sibling resources",
        8,
    )
    node_lb_partial_assert_task = named_yaml_sequence_item(
        node_lb_exercise,
        "Assert the exact surviving Service firewall identity after partial cleanup",
        8,
    )
    retained_service_firewall_reference = (
        "{{ e2e_node_lb_result.services['inspace-e2e-node-traefik'].firewallUUID }}"
    )
    require(
        "--retained-service-firewall" in node_lb_partial_task
        and retained_service_firewall_reference in node_lb_partial_task
        and "e2e_node_lb_partial_result.retainedServiceFirewallUUID =="
        in node_lb_partial_assert_task
        and "e2e_node_lb_result.services['inspace-e2e-node-traefik'].firewallUUID"
        in node_lb_partial_assert_task,
        "partial Node-LB cleanup must pass and assert the exact surviving Service firewall UUID",
    )
    node_lb_shared_gate = named_yaml_sequence_item(
        node_lb_exercise,
        "Require the mixed Traefik and sibling Services to establish one shared shadow shard",
        8,
    )
    require_yaml_key(node_lb_shared_gate, 10, "retries", "180")
    require_yaml_key(node_lb_shared_gate, 10, "delay", "10")
    require("all(.items[]; .spec.loadBalancerClass != \"io.cilium/node\")" not in test_playbook,
            "live acceptance must not globally reject CCM-owned Cilium Node IPAM shadows")
    for cleanup_name in node_lb_service_names:
        require(f"service/{cleanup_name}" in cleanup,
                f"destroy fallback must remove Node-LB Service/{cleanup_name}")
    require("deployment/inspace-e2e-node-lb" in cleanup and
            "Wait for every managed Node-LB owner to quiesce" in cleanup and
            "Delete the generated Node-LB NodeClass after its owners are gone" in cleanup and
            "/opt/e2e/scripts/verify-node-load-balancer.py" in cleanup,
            "destroy fallback must quiesce every Node-LB Kubernetes and cloud owner")
    require(
        'state.get("nodeLoadBalancerForbiddenLoadBalancerNames", [])' in persist_workload
        and 'node_lb_names.add(f"k8s-{sha16(state[\'clusterName\'])}-{sha16(uid)}")'
        in persist_workload
        and 'state["nodeLoadBalancerForbiddenLoadBalancerNames"] = sorted(node_lb_names)'
        in persist_workload,
        "workload ownership recovery must durably journal every forbidden Node-LB generic NLB identity",
    )
    require("Cilium Node IPAM and `io.cilium/node` are disabled" not in readme and
            "defaults them to `public-node-shared`" in readme and
            "complete billable-resource" in readme,
            "E2E documentation must describe the live Node-LB default and exact cleanup proof")
    private_services = [
        manifest_document(workload, "Service", "inspace-e2e-private-a"),
        manifest_document(workload, "Service", "inspace-e2e-private-b"),
    ]
    private_ports = []
    for name, service in zip(("inspace-e2e-private-a", "inspace-e2e-private-b"), private_services):
        require("inspace.cloud/load-balancer-scope: private" in service,
                f"{name} must select the private Cilium pool")
        require("loadBalancerClass: io.cilium/l2-announcer" in service,
                f"{name} must use the Cilium L2 class")
        require("externalTrafficPolicy: Cluster" in service,
                f"{name} must use Cluster traffic policy")
        require(re.search(r"(?m)^\s+protocol: TCP$", service) is not None,
                f"{name} must expose TCP")
        ports = re.findall(r"(?m)^\s+port: ([0-9]+)$", service)
        require(len(ports) == 1, f"{name} must expose exactly one Service port")
        private_ports.append(ports[0])
    require(len(set(private_ports)) == 1,
            "the two private Cilium Services must reuse the same TCP port")
    require(workload.count("loadBalancerClass: io.cilium/l2-announcer") == 2,
            "exactly the two private Services must use the Cilium L2 class")
    require("io.cilium/node" not in workload,
            "E2E workloads must never use Cilium Node IPAM")

    public_service = manifest_document(workload, "Service", "inspace-e2e-web")
    require("inspace.cloud/load-balancer-scope: public" in public_service and
            'service.beta.kubernetes.io/inspace-load-balancer-public: "true"' in public_service,
            "public Service must use the exact InSpace scope and opt-in annotation")
    require("loadBalancerClass:" not in public_service,
            "public InSpace NLB Service must leave loadBalancerClass unset for generic CCM")
    require("externalTrafficPolicy: Local" in public_service,
            "public InSpace NLB Service must preserve source IP and use endpoint-local targets")
    require(re.search(r"(?m)^\s+protocol: TCP$", public_service) is not None,
            "public InSpace NLB Service must be TCP-only")

    node_lb_services = {
        name: manifest_document(node_load_balancer_workload, "Service", name)
        for name in node_lb_service_names
    }
    node_lb_ports = {}
    for name, service in node_lb_services.items():
        require("loadBalancerClass: inspace.cloud/node" in service,
                f"{name} must select the user-facing InSpace Node-LB class")
        require("allocateLoadBalancerNodePorts: false" in service,
                f"{name} must explicitly disable NodePorts")
        require("externalTrafficPolicy: Cluster" in service,
                f"{name} must use Cluster traffic policy")
        require("loadBalancerIP:" not in service and "externalIPs:" not in service,
                f"{name} must not bypass CCM address ownership")
        ports = re.findall(
            r"(?m)^    - name: [a-z0-9-]+\n"
            r"^      port: ([0-9]+)\n"
            r"^      targetPort: [a-z0-9-]+\n"
            r"^      protocol: (TCP|UDP)$",
            service,
        )
        require(bool(ports), f"{name} must expose an explicit TCP/UDP port contract")
        node_lb_ports[name] = {(protocol, int(port)) for port, protocol in ports}
    for name in node_lb_service_names[:3]:
        require("service.inspace.cloud/node-lb-mode:" not in node_lb_services[name],
                f"{name} must exercise the omitted-mode public-node-shared default")
    dedicated_node_lb_service = node_lb_services["inspace-e2e-node-dedicated"]
    require("service.inspace.cloud/node-lb-mode: public-node-dedicated" in dedicated_node_lb_service and
            "service.inspace.cloud/node-lb-cpu:" not in dedicated_node_lb_service and
            "service.inspace.cloud/node-lb-memory:" not in dedicated_node_lb_service,
            "dedicated live acceptance must exercise the default 1-vCPU/4-GiB shape")
    require(node_lb_ports["inspace-e2e-node-traefik"] ==
            {("TCP", 80), ("TCP", 443), ("UDP", 443)} and
            node_lb_ports["inspace-e2e-node-shared-conflict"] == {("TCP", 80)} and
            node_lb_ports["inspace-e2e-node-shared-b"] == {("TCP", 18081)} and
            node_lb_ports["inspace-e2e-node-dedicated"] == {("TCP", 18082)},
            "live Node-LB Services must prove mixed TCP/UDP, non-conflicting reuse, and TCP/80 auto-sharding")
    node_lb_deployment = manifest_document(
        node_load_balancer_workload, "Deployment", "inspace-e2e-node-lb"
    )
    require("karpenter.sh/nodepool: {{ e2e_nodepool_name }}" in node_lb_deployment and
            node_lb_deployment.count("docker.io/library/busybox:1.36.1@sha256:") == 5 and
            node_lb_deployment.count("exec httpd -f -p") == 4 and
            "nc -u -l -p 18443 -e /tmp/udp-echo" in node_lb_deployment and
            "node-traefik-http3" in node_lb_deployment,
            "Node-LB data-path workload must stay on the general worker and expose exact TCP/UDP markers")
    require(node_load_balancer_workload.count("loadBalancerClass: inspace.cloud/node") == 4 and
            "loadBalancerClass: io.cilium/node" not in node_load_balancer_workload,
            "only the CCM may create Cilium Node IPAM shadow Services")

    node_lb_module = load_script_module(
        "e2e_verify_node_load_balancer_static",
        ROOT / "scripts/verify-node-load-balancer.py",
    )
    require(node_lb_module.managed_name("cluster-a", "node-lb") == "cluster-a-node-lb",
            "Node-LB verifier does not mirror the managed NodeClass name")
    require(node_lb_module.firewall_name(
        "cluster-a", "01234567-89ab-4def-8123-456789abcdef", "deadbeef"
    ) == "inlb-34ab3e1c-01234567-89ab-4def-8123-456789abcdef-deadbeef",
            "Node-LB verifier does not mirror full-Service-UID firewall ownership")
    require(node_lb_module.cluster_icmp_firewall_name("cluster-a") ==
            ("inlb-34ab3e1c8c468878c75341efcf8fd3cd-icmp-564fcbd1", "564fcbd1"),
            "Node-LB verifier does not mirror 128-bit cluster ICMP firewall ownership")
    mixed_rules = [
        {
            "protocol": protocol.lower(), "direction": "inbound",
            "port_start": port, "port_end": port,
            "endpoint_spec_type": "any", "endpoint_spec": None,
        }
        for protocol, port in (("TCP", 80), ("TCP", 443), ("UDP", 443))
    ]
    require(node_lb_module.canonical_service_policy_hash(mixed_rules) == "0023bff0",
            "Node-LB verifier does not mirror the mixed TCP/UDP Service policy hash")

    cluster = "cluster-a"
    public_uid = "11111111-1111-4111-8111-111111111111"
    node_lb_uid = "22222222-2222-4222-8222-222222222222"
    public_nlb_name = node_lb_module.generic_nlb_name(cluster, public_uid)
    forbidden_nlb_name = node_lb_module.generic_nlb_name(cluster, node_lb_uid)
    nlb_state = {
        "clusterName": cluster,
        "serviceLoadBalancerName": public_nlb_name,
        "nodeLoadBalancerForbiddenLoadBalancerNames": [forbidden_nlb_name],
    }
    public_services = [{
        "metadata": {"namespace": "default", "name": "inspace-e2e-web", "uid": public_uid},
    }]
    unrelated_and_public_nlbs = [
        {"uuid": "unrelated", "display_name": "account-owner-nlb"},
        {"uuid": "paid-public", "display_name": public_nlb_name},
    ]
    require(
        node_lb_module.owned_node_load_balancer_nlbs(
            nlb_state, public_services, unrelated_and_public_nlbs
        ) == [],
        "Node-LB NLB detector attributed an unrelated or exact paid public baseline NLB",
    )
    owned_nlb_cases = (
        ("journaled", forbidden_nlb_name),
        ("cluster-prefix", f"k8s-{node_lb_module.hash16(cluster)}-aaaaaaaaaaaaaaaa"),
        ("service-policy-prefix", f"inlb-{node_lb_module.short_hash(cluster)}-unexpected"),
        ("icmp-policy-prefix", f"inlb-{node_lb_module.ownership_hash(cluster)}-icmp-unexpected"),
    )
    for identity, name in owned_nlb_cases:
        require(
            node_lb_module.owned_node_load_balancer_nlbs(
                nlb_state, public_services, [{"uuid": identity, "display_name": name}]
            ) == [identity],
            f"Node-LB NLB detector missed {identity}",
        )

    original_node_lb_api_get = node_lb_module.api_get
    original_node_lb_kubectl = node_lb_module.kubectl
    node_lb_module.kubectl = lambda _kubeconfig, *_arguments: {"items": []}
    node_lb_module.api_get = lambda path: (
        [{"uuid": "stale-paid", "display_name": forbidden_nlb_name}]
        if path == "network/load_balancers" else []
    )
    try:
        with tempfile.TemporaryDirectory() as directory:
            immutable_baseline = pathlib.Path(directory) / "baseline-inventory.json"
            immutable_baseline.write_text(json.dumps({
                "vms": [], "firewalls": [], "floatingIPs": [],
                "loadBalancers": [], "disks": [],
            }), encoding="utf-8")
            immutable_baseline.chmod(0o600)
            try:
                node_lb_module.prove_absent(
                    nlb_state, "/unused/kubeconfig", immutable_baseline
                )
            except SystemExit as error:
                require("must not enter a new baseline" in str(error),
                        "Node-LB absence proof returned the wrong stale paid-NLB diagnostic")
            else:
                require(False, "Node-LB absence proof accepted an active owned paid NLB")

            node_lb_module.api_get = lambda path: (
                [{"uuid": "unexpected-paid", "display_name": "unrelated-name"}]
                if path == "network/load_balancers" else []
            )
            try:
                node_lb_module.prove_absent(
                    {"clusterName": cluster}, "/unused/kubeconfig", immutable_baseline
                )
            except SystemExit as error:
                require("immutable pre-mutation account baseline" in str(error),
                        "Node-LB absence proof returned the wrong immutable NLB diagnostic")
            else:
                require(False, "Node-LB absence proof normalized an unjournaled active NLB")
    finally:
        node_lb_module.api_get = original_node_lb_api_get
        node_lb_module.kubectl = original_node_lb_kubectl

    original_prove_present = node_lb_module.prove_present
    node_lb_module.prove_present = lambda *_arguments: {
        "firewalls": ["retained-replacement"],
        "icmpFirewallUUID": "icmp-original",
        "services": {
            "inspace-e2e-node-traefik": {
                "shard": "inlb-deadbeef",
                "vmUUID": "vm-original",
                "ip": "203.0.113.10",
                "firewallUUID": "retained-replacement",
            },
        },
    }
    try:
        node_lb_module.prove_partial(
            {}, "/unused/kubeconfig", pathlib.Path("/unused/baseline"),
            "33333333-3333-4333-8333-333333333333",
            "inlb-deadbeef", "vm-original", "203.0.113.10", "icmp-original",
            "retained-original",
        )
    except SystemExit as error:
        require("replaced the retained sibling Service firewall" in str(error),
                "partial cleanup proof returned the wrong retained-firewall diagnostic")
    else:
        require(False, "partial cleanup proof accepted a replacement sibling Service firewall")
    finally:
        node_lb_module.prove_present = original_prove_present

    require(node_lb_module.floating_ip_name("cluster-a", "inlb-deadbeef") ==
            "karpenter-inlb-deadbeef-fd7cd81d52",
            "Node-LB verifier does not mirror Karpenter FIP ownership")
    for accepted_nonvirtual in (None, False):
        node_lb_module.require_nonvirtual(accepted_nonvirtual, "static")
    for contradictory_nonvirtual in (True, 0, "false", [], {}):
        try:
            node_lb_module.require_nonvirtual(contradictory_nonvirtual, "static")
        except SystemExit as error:
            require("non-virtual InSpace address" in str(error),
                    "Node-LB verifier returned the wrong virtual-FIP diagnostic")
        else:
            require(False, f"Node-LB verifier accepted invalid is_virtual={contradictory_nonvirtual!r}")
    for marker in (
        'NODE_LOAD_BALANCER_CLASS = "inspace.cloud/node"',
        'CILIUM_NODE_CLASS = "io.cilium/node"',
        '"inspace.cloud/instance-cpu": ("In", ("1",))',
        '"inspace.cloud/instance-memory": ("In", ("4096",))',
        '"inspace.cloud/host-class": ("In", ("amd-epyc",))',
        'nodeclass_spec.get("rootDiskGiB") == 30',
        'nodeclass_spec.get("reservePublicIPv4") is True',
        '"inspace.cloud/node-lb"',
        '"inspace.cloud.node-restriction.kubernetes.io/node-lb"',
        '"inspace.cloud.node-restriction.kubernetes.io/ready"',
        'nodeclaim_status.get("providerID") == node.get("spec", {}).get("providerID")',
        '"NoSchedule"',
        'active_node_lb_vm_uuids == expected_vm_uuids',
        'active_node_lb_fip_names == expected_fip_names',
        'expected_service_firewalls | {icmp_firewall_uuid}',
        'icmp_rules[0].get("port_start") is None',
        'canonical TCP/UDP-only policy',
        'cluster ICMP firewall must target every and only authoritative Node-LB VM',
        'ping_public_ip(address)',
        'probe_udp(result["ip"], port["port"]',
        'PARTIAL_DELETED_SERVICE = "inspace-e2e-node-shared-b"',
        'deleted shared-member Service firewall is still active',
        'owned_node_load_balancer_nlbs(state, all_services, load_balancers)',
        'must not enter a new baseline',
        'if current_nlb_uuids != immutable_nlb_uuids:',
        'immutable pre-mutation account baseline',
        'retained["firewallUUID"] == retained_service_firewall_uuid',
        'result["retainedServiceFirewallUUID"] = retained["firewallUUID"]',
        'replaced the retained sibling Service firewall',
        'Cilium Node IPAM acceptance must not create an InSpace NLB',
    ):
        require(marker in node_load_balancer_cloud,
                f"Node-LB live verifier is missing contract marker: {marker}")

    require('"default-lb-service-ipam"] == "none"' in playbook and
            "nodeIPAM:[[:space:]]*$" in playbook and
            "enabled:[[:space:]]*true" in playbook,
            "live Cilium checks must disable default LB claiming and enable explicit Node IPAM")
    require('"cilium.io/IPAMRequestSatisfied"' in playbook and
            'startswith("cilium.io/")' in playbook and
            '"io.cilium/lb-ipam-request-satisfied"' not in playbook and
            'startswith("io.cilium/")' not in playbook,
            "live Service checks must use the current Cilium status-condition namespace")
    require(playbook.count("use_proxy: false") >= 4,
            "live HTTP probes must bypass ambient controller proxies")
    require("e2e-persistence-sentinel" in playbook and
            playbook.count("persistence-sentinel") >= 3,
            "CSI replacement proof must read data created after initialization")
    require("ready-api-monitor" in playbook and "Wait for the continuity monitor first successful API probe" in playbook,
            "kube-vip failover must wait for a successful monitor probe before disruption")
    require(playbook.count("kube-vip Lease holder does not resolve to exactly one control-plane pod by node name") == 3 and
            playbook.count("select(.spec.nodeName == $holder)]") == 3 and
            playbook.count("then .[0].spec.nodeName else error") == 3 and
            ".metadata.name == $holder" not in playbook,
            "kube-vip ownership must correlate its node-name Lease identity to exactly one control-plane pod")
    kube_vip_ready = named_yaml_sequence_item(
        playbook, "Prove three pinned kube-vip mirror pods and one elected lease holder", 4
    )
    for marker in (
        '.ip == "127.0.0.1"',
        'any(.hostnames[]?; . == "kubernetes")',
        '.hostPath.path == "/etc/rancher/rke2/rke2.yaml"',
        '.hostPath.type == "File"',
        '.mountPath == "/etc/kubernetes/admin.conf"',
        '.readOnly == true',
        '(.securityContext.capabilities.drop // []) | sort) == ["ALL"]',
        '(.securityContext.capabilities.add // []) | sort) == ["NET_ADMIN", "NET_RAW"]',
    ):
        require(marker in kube_vip_ready,
                f"live kube-vip mirror-Pod proof is missing: {marker}")
    require('([.env[]? | select(.name == "k8s_config_file")] | length) == 0' in kube_vip_ready,
            "live kube-vip proof must reject the ineffective k8s_config_file override")
    require('select(.name == "vip_nodename" and' in kube_vip_ready and
            '.valueFrom.fieldRef.fieldPath == "spec.nodeName")] | length) == 1' in kube_vip_ready,
            "live kube-vip proof must require exactly one downward-API node-name identity")
    require('--arg image "{{ e2e_state.bootstrapCacheRegistry }}/kube-vip/kube-vip:v1.2.1@sha256:' in kube_vip_ready and
            '.image == $image' in kube_vip_ready,
            "live kube-vip proof must bind and compare the exact cached image")
    require('/var/lib/rancher/rke2/agent/pod-manifests/kube-vip.yaml.e2e-disabled' not in playbook,
            "kube-vip failover must move the manifest outside the kubelet static-pod directory")
    for lease in (
        "cilium-l2announce-default-inspace-e2e-private-a",
        "cilium-l2announce-default-inspace-e2e-private-b",
    ):
        service_name = lease.removeprefix("cilium-l2announce-default-")
        require(lease in playbook or
                ('lease="cilium-l2announce-default-$service"' in playbook and service_name in playbook),
                f"playbook must verify private L2 lease {lease}")
        require(lease in cleanup, f"cleanup must wait for private L2 lease {lease}")
    require("cilium.io/IPsUsed" in cleanup and
            "Wait for private Cilium L2 leases and LB IPAM allocations to quiesce" in cleanup,
            "cleanup must release both private VIPs before Karpenter teardown")

    require("private Cilium L2 Service unexpectedly owns an InSpace NLB" in service_cloud and
            "private Cilium L2 Service unexpectedly owns an InSpace FIP" in service_cloud and
            'choices=("present", "absent")' in service_cloud and
            "public Service NLB/FIP cleanup has not completed" in service_cloud and
            "immutable_load_balancer_baseline" in service_cloud and
            "require_exact_load_balancer_inventory" in service_cloud and
            "immutable pre-mutation account baseline" in service_cloud,
            "service cloud verifier must prove private zero ownership, public transition cleanup, and exact immutable NLB inventory")
    service_cloud_module = load_script_module(
        "e2e_verify_service_cloud_static", ROOT / "scripts/verify-service-cloud.py"
    )
    with tempfile.TemporaryDirectory() as directory:
        immutable_baseline = pathlib.Path(directory) / "baseline-inventory.json"
        immutable_baseline.write_text(json.dumps({
            "vms": [],
            "firewalls": [],
            "floatingIPs": [],
            "loadBalancers": ["baseline-nlb"],
            "disks": [],
        }), encoding="utf-8")
        immutable_baseline.chmod(0o600)
        service_cloud_module.require_exact_load_balancer_inventory(
            [{"uuid": "baseline-nlb"}], immutable_baseline
        )
        service_cloud_module.require_exact_load_balancer_inventory(
            [
                {"uuid": "baseline-nlb"},
                {"uuid": "paid-service-nlb"},
                {"uuid": "deleted-nlb", "status": "deleted"},
            ],
            immutable_baseline,
            "paid-service-nlb",
        )
        for label, inventory, allowed_paid_nlb in (
            (
                "present unrelated NLB",
                [
                    {"uuid": "baseline-nlb"},
                    {"uuid": "paid-service-nlb"},
                    {"uuid": "unexpected-nlb"},
                ],
                "paid-service-nlb",
            ),
            (
                "stale recovery NLB",
                [{"uuid": "baseline-nlb"}, {"uuid": "stale-nlb"}],
                None,
            ),
        ):
            try:
                service_cloud_module.require_exact_load_balancer_inventory(
                    inventory, immutable_baseline, allowed_paid_nlb
                )
            except SystemExit as error:
                require(
                    "immutable pre-mutation account baseline" in str(error),
                    f"service cloud verifier returned the wrong {label} diagnostic",
                )
            else:
                require(False, f"service cloud verifier normalized a {label}")
    for accepted_nonvirtual in (None, False):
        service_cloud_module.require_nonvirtual_flag(accepted_nonvirtual)
    for contradictory_nonvirtual in (True, 0, "false", [], {}):
        try:
            service_cloud_module.require_nonvirtual_flag(contradictory_nonvirtual)
        except SystemExit as error:
            require("non-virtual InSpace address" in str(error),
                    "service cloud verifier returned the wrong virtual-FIP diagnostic")
        else:
            require(False, f"service cloud verifier accepted invalid is_virtual={contradictory_nonvirtual!r}")
    require("private_address == control_plane_vip" in service_cloud,
            "public Service proof must reject a control-plane VIP collision")
    require("target must be exactly the eligible Ready worker" in service_cloud and
            "targets must be empty without an eligible Ready target" in service_cloud and
            "exactly one TCP 80-to-30080 forwarding rule" in service_cloud,
            "public Service proof must bind the exact NLB forwarding and VM target contracts")
    cluster_policy_exercise = named_yaml_sequence_item(
        test_playbook, "Exercise control-plane exclusion under Cluster traffic policy", 4
    )
    require("Switch the public Service to Cluster traffic policy" in cluster_policy_exercise and
            "Require Cluster policy and exactly three Ready control-plane nodes" in cluster_policy_exercise and
            "Require Cluster public NLB target to remain exactly the eligible Ready worker" in cluster_policy_exercise and
            "\n      always:\n" in cluster_policy_exercise and
            "Restore the public Service to Local traffic policy" in cluster_policy_exercise and
            "Require restored Local policy and exact eligible Ready worker target" in cluster_policy_exercise and
            '{"spec":{"externalTrafficPolicy":"Cluster"}}' in cluster_policy_exercise and
            '{"spec":{"externalTrafficPolicy":"Local"}}' in cluster_policy_exercise and
            "node-role.kubernetes.io/control-plane" in cluster_policy_exercise and
            "node-role.kubernetes.io/master" in cluster_policy_exercise,
            "live public NLB acceptance must prove control-plane exclusion under Cluster policy and restore Local")
    require("node.kubernetes.io/exclude-from-external-load-balancers=true" in playbook and
            "Require the public NLB to remove the excluded local-endpoint node" in playbook and
            "Require zero public NLB targets without a ready local endpoint" in playbook and
            playbook.count("--targets") >= 6,
            "live public NLB acceptance must prove Node and EndpointSlice target removal/restoration")
    service_cloud_invocations = test_playbook.split(
        "/opt/e2e/scripts/verify-service-cloud.py"
    )[1:]
    require(
        len(service_cloud_invocations) == 11
        and all(
            "--immutable-baseline" in invocation[:200]
            and "{{ e2e_baseline_inventory_file }}" in invocation[:200]
            for invocation in service_cloud_invocations
        )
        and "service.beta.kubernetes.io/inspace-load-balancer-public" in playbook,
            "every paid-Service cloud proof must anchor NLB inventory to the immutable pre-mutation baseline")
    require("Remove only the public scope label while keeping the annotation and Service type" in playbook and
            "Restore only the public scope label to recreate the NLB" in playbook and
            "inspace.cloud/load-balancer-scope-" in playbook,
            "live public lifecycle must prove label-only cleanup and recreation")
    require(playbook.count("systemctl is-enabled ufw.service") == 3 and
            playbook.count("systemctl is-active --quiet ufw.service") == 3 and
            playbook.count("systemctl show ufw.service --property=LoadState --value") == 3 and
            playbook.count("not-found) ;;") == 3,
            "control planes, worker, and bastion must prove guest UFW is disabled and inactive")
    require("Disable automatic APT update units on repaired control planes" in playbook and
            playbook.count("for apt_unit in apt-daily.service") == 5 and
            playbook.count('APT::Periodic::Enable "0";') == 4 and
            playbook.count('APT::Periodic::Update-Package-Lists "0";') == 4 and
            playbook.count('APT::Periodic::Unattended-Upgrade "0";') == 4 and
            playbook.count('systemctl is-enabled "$apt_unit"') == 4,
            "control planes (including repair), worker, and bastion must prove automatic APT updates are masked")
    upstream_digest = "sha256:49b77655f9f109bedc5eb25723bb0e4c57d8513ba33cc69c31be3f243eb2386d"
    cached_digest = "sha256:44035f68040c9eb99103c65f1f9ab9698d93f9f272110825705338ac1926f3d9"
    require(init_playbook.count(upstream_digest) == 1,
            "preflight must audit the upstream multiarch kube-vip manifest exactly once")
    require(init_playbook.count(cached_digest) >= 2,
            "control-plane manifests and live pods must use the cached amd64 kube-vip digest")
    require("expected one exact egress FIP for each control plane and bastion" in bootstrap_discovery and
            "vm_by_name = canonical_owned_vm_details(listed_owned_vms)" in bootstrap_discovery and
            'expected_cp_names = [f"{cluster_resource_name}-cp{index}"' in bootstrap_discovery and
            "validate_optional_vm_hostname(vm, name, name)" in bootstrap_discovery and
            "user-resource/vm?" in bootstrap_discovery and
            "enabled non-virtual InSpace type=public FIP" in bootstrap_discovery and
            'assigned_to_resource_type") != "virtual_machine"' in bootstrap_discovery and
            "private-VIP bootstrap must not create or adopt a control-plane load balancer" in bootstrap_discovery and
            "2-vCPU / 4-GiB / 60-GiB control-plane shape" in bootstrap_discovery and
            "1-vCPU / 2-GiB / 30-GiB / configured-pool shape" in bootstrap_discovery and
            "bootstrap FIPs must have the exact configured billing-account identity" in bootstrap_discovery and
            "VM public_ipv4 must remain empty for an auto-reserved FIP" in bootstrap_discovery and
            "bastion VM public_ipv4 must remain empty for an auto-reserved FIP" in bootstrap_discovery and
            "node firewall must be assigned to exactly the three control-plane VMs" in bootstrap_discovery and
            "bastion public ingress must be only configured management TCP/22 and portless ICMP" in bootstrap_discovery,
            "bootstrap discovery must prove exact VM FIPs, zero control NLBs, and firewall isolation")
    require('test "$(hostname)" = "{{ e2e_node_name }}"' in playbook and
            "[.controlPlanes[].name] | sort" in playbook and
            "[.items[].metadata.name] | sort" in playbook,
            "live E2E must bind cloud, guest-hostname, and Kubernetes control-plane identities")

    bastion_play = named_yaml_sequence_item(playbook, "Establish the pinned public bastion", 0)
    bastion_ping = named_yaml_sequence_item(
        bastion_play, "Prove the bastion FIP answers ICMP from the management client", 4
    )
    require('argv: [ping, -4, -c, "3", -W, "5", "{{ e2e_public_ip }}"]' in bastion_ping and
            "delegate_to: localhost" in bastion_ping and
            "retries: 12" in bastion_ping and
            "until: e2e_bastion_ping.rc == 0" in bastion_ping,
            "live bootstrap must prove the management-scoped bastion ICMP path")
    bastion_cloud_init = named_yaml_sequence_item(
        bastion_play, "Wait for bounded bastion cloud-init completion", 4
    )
    require("timeout --kill-after=5s 4800s sh -c" in bastion_cloud_init,
            "bastion cloud-init wait must cover bounded cold-cache initialization")
    for hostname_proof in (
        'test "$(hostname)" = "{{ e2e_node_name }}"',
        'test "$(hostnamectl --static)" = "{{ e2e_node_name }}"',
        'test "$(tr -d \'\\n\' </etc/hostname)" = "{{ e2e_node_name }}"',
    ):
        require(hostname_proof in bastion_play,
                f"bastion guest identity proof is missing: {hostname_proof}")
    worker_play = named_yaml_sequence_item(
        playbook, "Verify the dynamically provisioned RKE2 worker", 0
    )
    worker_contract = named_yaml_sequence_item(
        worker_play, "Verify cloud-init Ubuntu and the RKE2 agent", 4
    )
    for role, contract in (
        ("bastion", bastion_play),
        ("control plane", control_plane_contract),
        ("worker", worker_contract),
    ):
        for hostname_mapping_proof in (
            'test "$(awk \'$1 == "127.0.1.1" { count++ } END { print count + 0 }\' /etc/hosts)" -eq 1',
            "grep -Eq '^127\\.0\\.1\\.1[[:space:]]+{{ e2e_node_name }}([[:space:]]|$)' /etc/hosts",
            'getent hosts "{{ e2e_node_name }}" | grep -Eq \'^127\\.0\\.1\\.1[[:space:]]\'',
        ):
            require(hostname_mapping_proof in contract,
                    f"{role} hostname mapping proof is missing: {hostname_mapping_proof}")
    bastion_cache = named_yaml_sequence_item(
        bastion_play, "Prove the default bastion cache is mounted healthy complete and read-only", 4
    )
    for marker in (
        "stat -c %s /var/lib/inspace/bootstrap-cache.img",
        "10000000000",
        "mountpoint -q /var/lib/inspace/bootstrap-cache",
        "findmnt -n -o FSTYPE /var/lib/inspace/bootstrap-cache",
        "docker compose -f \"$compose_file\" ps --services --status running",
        "docker inspect --format",
        ".State.Health.Status",
        "Public Key Algorithm: id-ecPublicKey",
        "ASN1 OID: prime256v1",
        '-verify_hostname "$cache_host"',
        'cmp -s /etc/inspace-cache/tls/server.crt "$served_certificate"',
        "/etc/inspace-cache/images.tsv)\" -eq 32",
        '$2 == "rancher/kube-webhook-certgen:v1.14.5-hardened2" { count++ } END { print count + 0 }\' /etc/inspace-cache/images.tsv)" -eq 0',
        '$2 == "rancher/nginx-ingress-controller:v1.14.5-hardened2" { count++ } END { print count + 0 }\' /etc/inspace-cache/images.tsv)" -eq 0',
        'test "$image_count" -eq 32',
        '"${resolve[@]}" "$cache_endpoint/healthz"',
        '"${resolve[@]}" "$cache_endpoint/v2/"',
        '"$cache_endpoint/v2/$repository/manifests/$reference"',
        "--request POST",
        'test "$write_status" = 403',
    ):
        require(marker in bastion_cache, f"bastion cache acceptance is missing: {marker}")
    require('docker inspect "$container_id" | grep -Fq' not in bastion_cache,
            "bastion health acceptance must not use an early-closing grep pipeline under pipefail")
    require('test "$cache_address" = "{{ e2e_private_ip }}"' in bastion_cache,
            "bastion cache acceptance must use the allocator-assigned bastion private address")
    require('e2e_node_name: "{{ e2e_state.bastionName }}"' in playbook,
            "dynamic bastion inventory must use the discovered exact VM name")
    for field in (
        '"bootstrapCacheAddress": bastion_private',
        '"bootstrapCacheEndpoint": cache_endpoint',
        '"bootstrapCacheRegistry": cache_registry',
        '"bootstrapCacheCABundle": cache_ca_bundle',
    ):
        require(field in bootstrap_discovery,
                f"bootstrap discovery does not persist the reconciled cache contract: {field}")
    for naming_contract in (
        're.compile(r"[a-z0-9](?:[a-z0-9-]{0,53}[a-z0-9])?")',
        'f"{cluster_resource_name}-bastion-{owner}"',
        'f"{cluster_resource_name}-bastion-ip"',
        'bastion_name, bastion_firewall_name, bastion_fip_name = bastion_resource_names(',
        'rf"inspace-rke2-bastion/v6 owner={re.escape(owner)} spec=[0-9a-f]{{64}}"',
        'rf"inspace-rke2-cp/v7 owner={re.escape(owner)} slot={slot} spec=[0-9a-f]{{64}}"',
        'validate_optional_vm_hostname(bastion, bastion_name, "bastion")',
        '"bastionName": bastion_name',
        '"bastionFloatingIPName": bastion_fip["name"]',
    ):
        require(naming_contract in bootstrap_discovery,
                f"bootstrap bastion naming contract is missing: {naming_contract}")
    require('expected_fip_names = set(expected_cp_fip_names) | {bastion_fip_name}' in bootstrap_discovery and
            'expected_cp_fip_names = [f"{cluster_resource_name}-cp{slot}-ip"' in bootstrap_discovery and
            'node_firewall_name = f"{cluster_resource_name}-nodes-{owner}"' in bootstrap_discovery,
            "bootstrap FIP and firewall names must use the cluster prefix")

    bootstrap_discovery_module = load_script_module(
        "e2e_discover_bootstrap_static", ROOT / "scripts/discover-bootstrap.py"
    )
    require(bootstrap_discovery_module.require_cluster_resource_name("a" * 55) == "a" * 55,
            "bootstrap discovery rejected the longest valid cluster resource name")
    try:
        bootstrap_discovery_module.require_cluster_resource_name("a" * 56)
    except SystemExit:
        pass
    else:
        require(False, "bootstrap discovery accepted a cluster resource name longer than 55 characters")
    bastion_names = bootstrap_discovery_module.bastion_resource_names("inspace-e2e-unit", "owner")
    require(
        bastion_names == (
            "inspace-e2e-unit-bastion",
            "inspace-e2e-unit-bastion-owner",
            "inspace-e2e-unit-bastion-ip",
        )
        and bastion_names[0] != bastion_names[1]
        and bastion_names[0] != bastion_names[2],
        "bastion VM name must be distinct from cluster-prefixed firewall and FIP names",
    )
    bastion_vm_uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    management_cidr = "203.0.113.7/32"
    private_subnet = "10.91.72.0/24"
    bastion_egress = [
        {
            "direction": "outbound",
            "protocol": protocol,
            "port_start": None,
            "port_end": None,
            "endpoint_spec_type": "any",
            "endpoint_spec": None,
        }
        for protocol in ("tcp", "udp", "icmp")
    ]
    bastion_ssh_ingress = {
        "direction": "inbound",
        "protocol": "tcp",
        "port_start": 22,
        "port_end": 22,
        "endpoint_spec_type": "ip_prefixes",
        "endpoint_spec": [management_cidr],
    }
    bastion_cache_ingress = {
        "direction": "inbound",
        "protocol": "tcp",
        "port_start": 8443,
        "port_end": 8443,
        "endpoint_spec_type": "ip_prefixes",
        "endpoint_spec": [private_subnet],
    }
    bastion_icmp_ingress = {
        "direction": "inbound",
        "protocol": "icmp",
        "port_start": None,
        "port_end": None,
        "endpoint_spec_type": "ip_prefixes",
        "endpoint_spec": [management_cidr],
    }
    bastion_assignments = [{"resource_type": "vm", "resource_uuid": bastion_vm_uuid}]
    bootstrap_discovery_module.validate_bastion_firewall(
        {
            "resources_assigned": bastion_assignments,
            "rules": bastion_egress + [bastion_ssh_ingress, bastion_icmp_ingress, bastion_cache_ingress],
        },
        management_cidr,
        private_subnet,
        bastion_vm_uuid,
        cache_enabled=True,
    )
    bootstrap_discovery_module.validate_bastion_firewall(
        {
            "resources_assigned": bastion_assignments,
            "rules": bastion_egress + [bastion_ssh_ingress, bastion_icmp_ingress],
        },
        management_cidr,
        private_subnet,
        bastion_vm_uuid,
        cache_enabled=False,
    )
    any_management_cidr = "0.0.0.0/0"
    any_ssh_ingress = dict(
        bastion_ssh_ingress,
        endpoint_spec_type="any",
        endpoint_spec=None,
    )
    any_icmp_ingress = dict(
        bastion_icmp_ingress,
        endpoint_spec_type="any",
        endpoint_spec=None,
    )
    bootstrap_discovery_module.validate_bastion_firewall(
        {
            "resources_assigned": bastion_assignments,
            "rules": bastion_egress + [any_ssh_ingress, any_icmp_ingress],
        },
        any_management_cidr,
        private_subnet,
        bastion_vm_uuid,
        cache_enabled=False,
    )
    wrong_any_icmp = dict(
        bastion_icmp_ingress,
        endpoint_spec_type="ip_prefixes",
        endpoint_spec=[any_management_cidr],
    )
    try:
        bootstrap_discovery_module.validate_bastion_firewall(
            {
                "resources_assigned": bastion_assignments,
                "rules": bastion_egress + [any_ssh_ingress, wrong_any_icmp],
            },
            any_management_cidr,
            private_subnet,
            bastion_vm_uuid,
            cache_enabled=False,
        )
    except SystemExit as error:
        require("portless ICMP" in str(error),
                "bootstrap discovery returned the wrong default-Any ICMP diagnostic")
    else:
        require(False, "bootstrap discovery accepted a noncanonical default-Any ICMP source")
    wrong_cache_ingress = dict(bastion_cache_ingress, endpoint_spec=[management_cidr])
    try:
        bootstrap_discovery_module.validate_bastion_firewall(
            {
                "resources_assigned": bastion_assignments,
                "rules": bastion_egress + [bastion_ssh_ingress, bastion_icmp_ingress, wrong_cache_ingress],
            },
            management_cidr,
            private_subnet,
            bastion_vm_uuid,
            cache_enabled=True,
        )
    except SystemExit as error:
        require("cache ingress" in str(error),
                "bootstrap discovery returned the wrong cache-ingress diagnostic")
    else:
        require(False, "bootstrap discovery accepted cache ingress from outside the VPC subnet")
    wrong_icmp_ingress = dict(bastion_icmp_ingress, endpoint_spec=["0.0.0.0/0"])
    try:
        bootstrap_discovery_module.validate_bastion_firewall(
            {
                "resources_assigned": bastion_assignments,
                "rules": bastion_egress + [bastion_ssh_ingress, wrong_icmp_ingress],
            },
            management_cidr,
            private_subnet,
            bastion_vm_uuid,
            cache_enabled=False,
        )
    except SystemExit as error:
        require("portless ICMP" in str(error),
                "bootstrap discovery returned the wrong bastion ICMP diagnostic")
    else:
        require(False, "bootstrap discovery accepted public bastion ICMP outside managementCIDR")
    for vm_detail in ({}, {"hostname": None}, {"hostname": ""}, {"hostname": bastion_names[0]}):
        bootstrap_discovery_module.validate_optional_vm_hostname(
            vm_detail, bastion_names[0], "unit bastion"
        )
    try:
        bootstrap_discovery_module.validate_optional_vm_hostname(
            {"hostname": bastion_names[1]}, bastion_names[0], "unit bastion"
        )
    except SystemExit as error:
        require("contradictory hostname" in str(error),
                "bootstrap discovery returned the wrong hostname contradiction diagnostic")
    else:
        require(False, "bootstrap discovery accepted the firewall name as the bastion hostname")
    require(
        bootstrap_discovery.count(
            'validate_optional_vm_hostname(bastion, bastion_name, "bastion")'
        ) == 1
        and bootstrap_discovery.count("validate_optional_vm_hostname(vm, name, name)") == 1,
        "production bootstrap discovery must validate optional API hostnames for bastion and control planes",
    )
    expected_network_uuid = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
    for vm_detail in (
        {},
        {"network_uuid": None},
        {"network_uuid": ""},
        {"network_uuid": expected_network_uuid},
    ):
        bootstrap_discovery_module.validate_optional_vm_network_uuid(
            vm_detail, expected_network_uuid, "unit VM"
        )
    for contradictory_network in (
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        " ",
        0,
        [],
    ):
        try:
            bootstrap_discovery_module.validate_optional_vm_network_uuid(
                {"network_uuid": contradictory_network}, expected_network_uuid, "unit VM"
            )
        except SystemExit as error:
            require("contradicts the configured VPC" in str(error),
                    "bootstrap discovery returned the wrong network contradiction diagnostic")
        else:
            require(False, f"bootstrap discovery accepted contradictory VM network {contradictory_network!r}")
    require(
        bootstrap_discovery.count(
            'validate_optional_vm_network_uuid(bastion, network_uuid, "bastion")'
        ) == 1
        and bootstrap_discovery.count(
            "validate_optional_vm_network_uuid(vm, network_uuid, name)"
        ) == 1
        and "network_members.count(vm_uuid) != 1" in bootstrap_discovery
        and 'subnet = ipaddress.ip_network(network["subnet"], strict=False)' in bootstrap_discovery
        and bootstrap_discovery.count("require_private_ipv4(") >= 3,
        "production bootstrap discovery must combine optional detail validation with exact VPC membership and subnet checks",
    )
    sparse_owned_vms = [
        {"uuid": "11111111-2222-4333-8444-555555555555", "name": "inspace-e2e-unit-cp0"},
        {"uuid": "66666666-7777-4888-8999-aaaaaaaaaaaa", "name": "inspace-e2e-unit-bastion"},
    ]
    canonical_vm_records = {
        item["uuid"]: {
            **item,
            "description": "persisted ownership",
            "network_uuid": expected_network_uuid,
            "designated_pool_uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "storage": [{"primary": True, "size": 30}],
        }
        for item in sparse_owned_vms
    }
    detail_queries = []

    def canonical_vm_getter(path: str):
        detail_queries.append(path)
        prefix = "user-resource/vm?uuid="
        require(path.startswith(prefix), "bootstrap VM detail lookup used the wrong endpoint")
        return canonical_vm_records[path.removeprefix(prefix)]

    canonical = bootstrap_discovery_module.canonical_owned_vm_details(
        sparse_owned_vms, canonical_vm_getter
    )
    require(set(canonical) == {item["name"] for item in sparse_owned_vms},
            "bootstrap VM detail canonicalization lost an owned name")
    require(all(item.get("network_uuid") for item in canonical.values()) and len(detail_queries) == 2,
            "bootstrap discovery did not replace every sparse list row with complete detail")

    raw_fip = {
        "enabled": True,
        "is_virtual": None,
        "type": "public",
        "address": "8.8.8.8",
    }
    require(
        bootstrap_discovery_module.require_usable_fip(raw_fip, "raw bootstrap FIP") == "8.8.8.8",
        "bootstrap discovery rejected a raw live non-virtual FIP with is_virtual=null",
    )
    for accepted_nonvirtual in (None, False):
        bootstrap_discovery_module.require_usable_fip(
            {**raw_fip, "is_virtual": accepted_nonvirtual}, "bootstrap FIP"
        )
    for contradictory_nonvirtual in (True, 0, "false", [], {}):
        try:
            bootstrap_discovery_module.require_usable_fip(
                {**raw_fip, "is_virtual": contradictory_nonvirtual}, "bootstrap FIP"
            )
        except SystemExit as error:
            require("enabled non-virtual" in str(error),
                    "bootstrap discovery returned the wrong virtual-FIP diagnostic")
        else:
            require(False, f"bootstrap discovery accepted invalid is_virtual={contradictory_nonvirtual!r}")

    def mismatched_vm_getter(_path: str):
        return {"uuid": sparse_owned_vms[0]["uuid"], "name": "foreign"}

    try:
        bootstrap_discovery_module.canonical_owned_vm_details(
            sparse_owned_vms[:1], mismatched_vm_getter
        )
    except SystemExit as error:
        require("does not match its list UUID/name" in str(error),
                "bootstrap discovery returned the wrong mismatch diagnostic")
    else:
        require(False, "bootstrap discovery accepted a mismatched canonical VM identity")

    detail_error = RuntimeError("injected detail lookup failure")

    def failing_vm_getter(_path: str):
        raise detail_error

    try:
        bootstrap_discovery_module.canonical_owned_vm_details(
            sparse_owned_vms[:1], failing_vm_getter
        )
    except RuntimeError as error:
        require(error is detail_error, "bootstrap discovery replaced the authoritative lookup error")
    else:
        require(False, "bootstrap discovery ignored an authoritative VM detail lookup failure")

    worker_discovery_module = load_script_module(
        "e2e_discover_worker_static", ROOT / "scripts/discover-worker.py"
    )
    for accepted_nonvirtual in (None, False):
        worker_discovery_module.require_nonvirtual_flag(accepted_nonvirtual, "raw worker FIP")
    for contradictory_nonvirtual in (True, 0, "false", [], {}):
        try:
            worker_discovery_module.require_nonvirtual_flag(
                contradictory_nonvirtual, "raw worker FIP"
            )
        except SystemExit as error:
            require("non-virtual InSpace address" in str(error),
                    "worker discovery returned the wrong virtual-FIP diagnostic")
        else:
            require(False, f"worker discovery accepted invalid is_virtual={contradictory_nonvirtual!r}")
    worker_name = "inspace-e2e-run-karp-general-abc123"
    worker_nodeclaim_name = "general-abc123"
    worker_fip_name = "karpenter-general-abc123-510fa6882d"
    require(
        worker_discovery_module.deterministic_floating_ip_name(
            "inspace-e2e-run", worker_nodeclaim_name
        ) == worker_fip_name,
        "worker discovery does not mirror the provider's deterministic v3 FIP name",
    )
    worker_summary = {"uuid": "12345678-1234-4abc-8def-1234567890ab", "name": worker_name}
    worker_detail = {
        **worker_summary,
        "hostname": worker_name,
        "public_ipv4": None,
        "description": json.dumps({
            "schema": "karpenter.inspace.cloud/v3",
            "cluster": "inspace-e2e-run",
            "nodeClaim": worker_nodeclaim_name,
            "vmName": worker_name,
            "floatingIPName": worker_fip_name,
            "hostClass": "amd-epyc",
        }),
        "designated_pool_uuid": "6976fdc8-4492-465b-bd16-9ad5f6b00b03",
        "storage": [
            {"uuid": "root-disk", "primary": True, "size": 100},
            {"uuid": "data-disk", "primary": False, "size": 20},
        ],
    }
    worker_detail_queries = []

    def worker_detail_getter(path: str):
        worker_detail_queries.append(path)
        return worker_detail

    canonical_worker = worker_discovery_module.canonical_worker_vm_detail(
        [worker_summary], worker_name, worker_nodeclaim_name,
        "inspace-e2e-run", "general", worker_detail_getter
    )
    require(canonical_worker is worker_detail and
            worker_detail_queries == ["user-resource/vm?uuid=12345678-1234-4abc-8def-1234567890ab"],
            "worker discovery did not resolve a sparse list identity through exact VM detail")
    worker_discovery_module.validate_worker_root_disk(worker_detail)
    invalid_worker_storage = (
        {},
        {"storage": None},
        {"storage": ["not-a-disk"]},
        {"storage": [{"primary": False, "size": 100}]},
        {"storage": [{"primary": True, "size": 99}]},
        {"storage": [
            {"primary": True, "size": 100},
            {"primary": True, "size": 100},
        ]},
    )
    for invalid_vm in invalid_worker_storage:
        try:
            worker_discovery_module.validate_worker_root_disk(invalid_vm)
        except SystemExit as error:
            require("worker VM" in str(error),
                    "worker root-disk validation returned the wrong diagnostic")
        else:
            require(False, f"worker discovery accepted invalid root storage {invalid_vm!r}")

    def mismatched_worker_getter(_path: str):
        return {**worker_detail, "name": "foreign-worker"}

    try:
        worker_discovery_module.canonical_worker_vm_detail(
            [worker_summary], worker_name, worker_nodeclaim_name,
            "inspace-e2e-run", "general", mismatched_worker_getter
        )
    except SystemExit as error:
        require("does not match the list UUID and Node name" in str(error),
                "worker canonicalization returned the wrong identity mismatch diagnostic")
    else:
        require(False, "worker discovery accepted a mismatched canonical VM detail")

    require("ProxyJump e2e-bastion" in ssh_config and "HostName {private}" in ssh_config,
            "all control-plane and worker SSH must use private IPs through the bastion")
    require("127.0.0.1:16443:$virtual_ip:6443" in tunnel and "StrictHostKeyChecking=yes" in tunnel,
            "Kubernetes API must use the pinned bastion local forward")
    require("setsid autossh -M 0" in tunnel and "AUTOSSH_GATETIME=0" in tunnel and
            "ServerAliveInterval=5" in tunnel and "ServerAliveCountMax=3" in tunnel,
            "Kubernetes API tunnel must automatically reconnect through a bounded autossh supervisor")
    require("api-tunnel.pid" in tunnel and "supervisor_identity" in tunnel and
            "read_process_metadata" in tunnel and "expected_start_time" in tunnel and
            "read_process_comm" in tunnel and "process_comm == autossh" in tunnel and
            "process_comm == ssh" in tunnel and
            "mapfile -d '' -t arguments" in tunnel and "arguments[0]##*/" in tunnel and
            "tunnel_ready" in tunnel and 'ss -H -ltnp "sport = :16443"' in tunnel and
            "tunnel_healthy" in tunnel and tunnel.count('supervisor_identity "$pid" "$expected_start_time"') >= 3 and
            "orphaned_tunnel_group_identity" in tunnel and "ssh_child_identity" in tunnel and
            "tunnel_arguments" in tunnel and "expected_arguments" in tunnel and
            "inspace-e2e-api-tunnel-instance" in tunnel and "record_token" in tunnel and
            "launch_cleanup_on_exit" in tunnel and "cleanup_failed_launch" in tunnel and
            "child_pid=$BASHPID" in tunnel and "child_group != \"$child_pid\"" in tunnel and
            "snapshot_verified_tunnel_members" in tunnel and "signal_verified_members" in tunnel and
            "containing an unverified live member" in tunnel and
            "unverified API tunnel process group" in tunnel and
            'kill "-$signal" "${pids[index]}"' in tunnel,
            "API tunnel stop must validate and terminate the complete supervisor process group")
    require('kill -TERM -- "-$pid"' not in tunnel and 'kill -KILL -- "-$pid"' not in tunnel,
            "API tunnel termination must not escalate through a reusable numeric process-group ID")
    require("openssl rand -hex 16" in entrypoint and
            "inspace-e2e-api-tunnel-instance" in entrypoint,
            "each phased runner container must have a unique API tunnel process identity")
    require("worker must not have an additional or foreign-named floating IPv4" in worker_discovery and
            "worker must be attached to exactly the intended managed cloud firewall" in worker_discovery and
            'require_nonvirtual_flag(address.get("is_virtual")' in worker_discovery and
            "managed node firewall must protect exactly three control planes and the worker" in worker_discovery and
            "worker InternalIP collides with the private control-plane VIP" in worker_discovery and
            'os.environ["INSPACE_AMD_HOST_POOL_UUID"]' in worker_discovery and
            "canonical_worker_vm_detail(" in worker_discovery and
            "validate_worker_root_disk(vm)" in worker_discovery and
            "exactly one 100-GiB primary root disk" in worker_discovery and
            'record.get("schema") != "karpenter.inspace.cloud/v3"' in worker_discovery and
            'record.get("nodeClaim") != node.get("nodeClaimName")' in worker_discovery and
            'record.get("vmName") != node.get("name")' in worker_discovery and
            'record.get("publicIPv4") not in (None, "")' in worker_discovery and
            'vm.get("public_ipv4") not in (None, "")' in worker_discovery and
            'address.get("billing_account_id") != billing_account' in worker_discovery and
            "deterministic_floating_ip_name(" in worker_discovery and
            "worker Node ExternalIP must equal its exact assigned FIP" in worker_discovery and
            'externalIPs:[$node.status.addresses[]|select(.type=="ExternalIP")|.address]' in playbook and
            "'.status.nodeName == $nodeName' <<<\"$nodeclaim\" >/dev/null" in playbook and
            'test "$(hostname)" = "{{ e2e_node_name }}"' in playbook and
            'record.get("hostClass") != "amd-epyc"' in worker_discovery and
            'vm.get("designated_pool_uuid") != amd_pool_uuid' in worker_discovery,
            "worker proof must bind exactly one egress FIP, exclude reserved VIPs, and bind the managed cloud firewall")
    require('($attachments | length) == 1' in playbook and
            '$attachments[0].spec.attacher == "csi.inspace.cloud"' in playbook and
            '$attachments[0].spec.nodeName == $worker' in playbook,
            "CSI proof must require one attachment on the sole Karpenter worker")

    for resource_path in (
        "user-resource/vm/list", "network/firewalls", "network/ip_addresses",
        "network/load_balancers", "storage/disks",
    ):
        require(resource_path in account_inventory,
                f"full account inventory is missing {resource_path}")
    require("returned a non-object resource item" in account_inventory and
            "refusing to replace an existing baseline inventory" in account_inventory and
            "baseline inventory must be a mode-0600 regular file" in account_inventory,
            "full account inventory must reject malformed API/baseline state")
    require("Capture every API-visible billable resource before mutation" in playbook and
            "Require the dedicated test account to contain no billable resources" in playbook and
            "Require the complete isolated-account inventory to match its baseline" in cleanup,
            "release acceptance must compare the entire isolated account to its empty baseline")
    require("def active_resources(" in cloud_audit and
            'item.get("is_deleted") is True' in cloud_audit and
            cloud_audit.count("active_resources(") == 6,
            "deterministic cleanup audit must ignore only explicitly deleted cloud rows")
    require('worker_vm_prefix = f"{args.cluster}-karp-{args.nodepool}-"' in cloud_audit and
            'worker_fip_prefix = f"karpenter-{args.nodepool}-"' in cloud_audit and
            'state.get("workerVMs", [])' in cloud_audit,
            "cleanup audit must retain new worker VM/FIP naming even with sparse list descriptions")
    require('f"{args.cluster}-nodes-{args.owner}"' in cloud_audit and
            'f"{args.cluster}-bastion-{args.owner}"' in cloud_audit and
            'f"{args.cluster}-bastion-ip"' in cloud_audit and
            'f"{args.cluster}-cp{slot}-ip"' in cloud_audit,
            "cleanup audit must retain cluster-prefixed bootstrap firewall/FIP naming")
    require('f"{args.cluster}-bastion"' in cloud_audit and
            'f"rke2-{args.owner}-bastion"' in cloud_audit and
            "or vm.get(\"name\") in bastion_vm_names" in cloud_audit,
            "cleanup audit must allow the current bastion VM and safe prior owner-derived VM name")
    cloud_audit_module = load_script_module("e2e_cloud_audit_static", ROOT / "scripts/cloud-audit.py")
    require(cloud_audit_module.parse_description('{"cluster":"expected"}') == {"cluster": "expected"},
            "cloud audit must parse structured VM ownership descriptions")
    cloud_audit_module.api_get = lambda _path: [
        {"uuid": "active"},
        {"uuid": "soft-deleted", "is_deleted": True},
        {"uuid": "status-deleted", "status": "DELETED"},
    ]
    require(list(cloud_audit_module.active_resources("test")) == [{"uuid": "active"}],
            "cloud audit active-resource predicate is broken")
    cloud_audit_module.api_get = lambda _path: ["malformed"]
    try:
        list(cloud_audit_module.active_resources("test"))
    except SystemExit:
        pass
    else:
        require(False, "cloud audit must reject non-object API resources")
    require("Require gratuitous ARP to update the existing VIP neighbor" in playbook and
            "Flush the VIP neighbor and prove fresh ARP" in playbook,
            "private L2 failover must separately prove GARP update and fresh ARP resolution")

    destroy_task = named_yaml_sequence_item(
        cleanup, "Destroy only bootstrap-controller-owned infrastructure synchronously", 4
    )
    require("\n      ansible.builtin.command:" in destroy_task and
            "\n      register: e2e_destroy_wait" in destroy_task and
            "\n      async:" not in destroy_task,
            "bootstrap destroy must remain attached to the managed Ansible process group")
    require("INSPACE_BOOTSTRAP_CACHE_KEY" not in destroy_task and
            "INSPACE_BOOTSTRAP_CACHE_NOT_BEFORE" not in destroy_task,
            "bootstrap destroy must not require cache key or certificate time input")
    ordering = [
        "Delete workload owners before infrastructure owners",
        "Wait for E2E pods PVs and VolumeAttachments to disappear",
        "Wait for private Cilium L2 leases and LB IPAM allocations to quiesce",
        "Delete the NodePool while Karpenter is still running",
        "Wait for owned NodeClaims and worker Nodes to disappear",
        "Delete the NodeClass after all worker ownership is gone",
        "Uninstall controllers only after their owners are quiescent",
        "Persist Kubernetes owner quiescence before bootstrap deletion",
        "Destroy only bootstrap-controller-owned infrastructure synchronously",
        "Require the final deterministic cloud audit to converge to zero",
        "Close the private API tunnel after the final zero audit",
    ]
    offsets = [cleanup.index(value) for value in ordering]
    require(offsets == sorted(offsets), "cleanup owner ordering changed")
    require(cleanup.index("Re-establish the container-local private API tunnel for cleanup") <
            cleanup.index("Wait for Kubernetes API reachability before owner quiescence"),
            "recovery must restore its private API tunnel before probing Kubernetes")
    require(re.search(r"preserving\s+cloud infrastructure is the fail-closed outcome", cleanup) is not None,
            "cleanup must fail closed when ownership is uncertain")
    require("e2e_cleanup_state.clusterResourceName + '-cp[0-2]|'" in cleanup and
            "e2e_cleanup_state.clusterResourceName + '-bastion|rke2-'" in cleanup and
            "e2e_cleanup_state.owner + '-(cp-[0-2]|bastion))$'" in cleanup,
            "controller uninstall must permit only current or fully legacy bootstrap VM names")
    print("E2E static contract verified (no live resources touched)")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError) as error:
        print(f"E2E static verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
