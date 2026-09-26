#!/usr/bin/env python3
"""Static, credential-free contracts for the operator deployment lifecycle."""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def require(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


def main() -> None:
    inventory = read("deploy/inventory.example.yml")
    gitignore = read(".gitignore")
    dockerignore = read(".dockerignore")
    dockerfile = read("deploy/Dockerfile")
    dependency_lock = read("deploy/requirements.lock.txt")
    container_entrypoint = read("deploy/container-entrypoint.sh")
    cluster_template = read("deploy/templates/cluster.yaml.j2")
    init = read("deploy/playbooks/init-cluster.yml")
    update = read("deploy/playbooks/update-control-plane.yml")
    destroy = read("deploy/playbooks/destroy-cluster.yml")
    preflight = read("deploy/playbooks/tasks/preflight.yml")
    cloud_crd = read(
        "modules/cloud-provider/config/crd/bases/"
        "infrastructure.inspace.cloud_inspaceclusters.yaml"
    )
    chart_crd = read(
        "charts/inspace-cloud-kube-modules-crds/templates/"
        "infrastructure.inspace.cloud_inspaceclusters.yaml"
    )

    require(
        re.search(r"(?m)^\s*(?:INSPACE_API_TOKEN|inspace_api_token)\s*:", inventory)
        is None,
        "example inventory stores a token",
    )
    egress_name = "Prove every control plane reaches the internet through its floating IP"
    require(
        egress_name in init
        and init.index(egress_name) < init.index("Wait for control-plane cloud-init completion"),
        "control-plane egress must be proven before the long cloud-init wait",
    )
    egress_task = init[init.index(egress_name):init.index("Wait for control-plane cloud-init completion")]
    require(
        '"inspace-cp{{ deploy_cp_index }}"' in egress_task
        and "https://registry-1.docker.io/v2/" in egress_task
        and "https://ghcr.io/v2/" in egress_task
        and " -f" not in egress_task
        and "timeout --kill-after=5s 300s sh -c" in egress_task
        and "'until curl " in egress_task,
        "control-plane egress must be proven from inside through the bastion",
    )
    # The local ssh client exits 255 only for its own transport failure. Retry
    # that alone, so one SSH blip cannot fail init while a real in-guest
    # timeout (124) or cloud-init error still fails on its single attempt.
    cloud_init_name = "Wait for control-plane cloud-init completion"
    cloud_init_task = init[init.index(cloud_init_name):init.index("Read the administrator kubeconfig from cp0")]
    for task, register, timeout in (
        (egress_task, "deploy_control_plane_egress", "300s"),
        (cloud_init_task, "deploy_control_plane_cloud_init", "2400s"),
    ):
        require(
            f"timeout --kill-after=5s {timeout} sh -c" in task
            and f"register: {register}\n" in task
            and f"until: {register}.rc != 255\n" in task
            and f"failed_when: {register}.rc != 0\n" in task
            and "retries: 3\n" in task
            and "delay: 10\n" in task,
            f"{register} must retry only ssh transport failures (255) around one {timeout} in-guest deadline",
        )

    karpenter_template = read("deploy/templates/karpenter.yaml.j2")
    readme = read("deploy/README.md")
    for label, template in (("cluster", cluster_template), ("Karpenter", karpenter_template)):
        require(
            'osVersion: "{{ deploy_os_version }}"' in template
            and '"26.04"' not in template
            and '"24.04"' not in template,
            f"{label} template must render the validated inventory os_version",
        )
    require(
        "deploy_os_version: \"{{ os_version | default(deploy_persisted_os_version, true) | string }}\"" in preflight
        and ".spec.controlPlane.machine.image.osVersion" in preflight
        and "if deploy_persisted_cluster_spec.stat.exists else '26.04'" in preflight
        and "deploy_os_version in ['24.04', '26.04']" in preflight
        and "deploy_os_version == '24.04' or modules_version is version('1.1.0-rc.3', '>=', version_type='semver')"
        in preflight
        and preflight.index("Require the complete deployment inventory")
        < preflight.index("Require cloud modules that accept the selected Ubuntu release"),
        "preflight must keep a persisted release (else 26.04), allow only 24.04/26.04, "
        "and require 1.1.0-rc.3+ for 26.04",
    )
    require(
        re.search(r"(?m)^    os_version: \"26\.04\"$", inventory) is not None
        and re.search(r"(?m)^    modules_version: 1\.1\.0-rc\.4$", inventory) is not None
        and "`os_version`" in readme,
        "example inventory and README must document os_version with a 26.04-capable modules_version",
    )
    for ignored in ("deploy/inventory.yml", "deploy/inventory/", "deploy/.state/"):
        require(ignored in gitignore, f"missing Git exclusion {ignored}")
        require(ignored in dockerignore, f"missing Docker exclusion {ignored}")
    require(
        "ubuntu:26.04@sha256:" in dockerfile
        and "docker:29.8.1-cli@sha256:" in dockerfile,
        "deploy runner base or Docker CLI image is not digest locked",
    )
    require(
        "ansible-core==2.21.4" in dependency_lock
        and all(
            line == "" or line.startswith("#") or re.search(r"^[A-Za-z0-9_.-]+==[^=]+$", line)
            for line in dependency_lock.splitlines()
        ),
        "deploy Python dependency lock contains an unpinned requirement",
    )
    require(
        "KUBECTL_VERSION=v1.36.4" in dockerfile
        and "alpine/helm:4.3.0@sha256:" in dockerfile
        and dockerfile.count("sha256sum --check") == 1,
        "deploy kubectl or Helm dependency is not exactly verified",
    )
    require(
        "replicas: {{ control_plane_replicas }}" in cluster_template,
        "cluster template pins a topology instead of using inventory",
    )
    require(
        "control_plane_replicas | int in [1, 3]" in preflight,
        "preflight does not reject two-server topology",
    )
    require(
        "control-plane replica count is immutable after cluster creation" in cloud_crd
        and "\n                        - 1\n                        - 3" in cloud_crd,
        "source CRD lacks immutable one-or-three replica contract",
    )
    require(cloud_crd == chart_crd, "source and packaged cluster CRDs differ")

    for fragment in (
        "cluster.desired.yaml",
        "persisted bootstrap spec differs",
        "deploy_persisted_bootstrap_spec_normalized",
        "INSPACE_ALLOW_REMOTE_MUTATIONS",
        "bootstrap_controller_version",
        "--until-ready",
        "discover_bootstrap.py",
        "tasks/start-tunnel.yml",
        "tasks/settle-single-control-plane.yml",
        "inspace-cloud-kube-modules-crds",
        "inspace-cloud-kube-modules",
        "tasks/apply-control-plane-config.yml",
    ):
        require(fragment in init, f"init lifecycle lacks {fragment}")
    require(
        init.index("cluster.desired.yaml") < init.index("--until-ready"),
        "desired-spec fence does not precede bootstrap mutation",
    )
    require(
        init.index("bootstrap-controller-version")
        < init.index("INSPACE_ALLOW_REMOTE_MUTATIONS"),
        "bootstrap destroy authority is not pinned before bootstrap mutation",
    )
    require(
        "ansible.builtin.import_tasks: tasks/settle-single-control-plane.yml" in init,
        "single-control-plane tasks are not statically parsed by syntax checks",
    )
    require(
        init.count("linux/amd64") == 2 and destroy.count("linux/amd64") == 2,
        "bootstrap controller pull/run does not pin the published x86 platform",
    )
    load_state = read("deploy/playbooks/tasks/load-state.yml")
    single_cp_settle = read("deploy/playbooks/tasks/settle-single-control-plane.yml")
    for fragment in (
        "control_plane_replicas | int == 1",
        "Temporarily make cp0 schedulable",
        "Wait for every expected RKE2 packaged install Job",
        "Temporarily remove the cloud-provider startup taint",
        "Restore the original cloud-provider startup taint",
        "Restore the durable control-plane NoSchedule taint",
        "zero-worker state",
    ):
        require(fragment in single_cp_settle, f"single-control-plane settling lacks {fragment}")
    for optional_false in ("skipOSUpgrade", "directDownload"):
        require(
            f".get('{optional_false}', false)" in load_state,
            f"persisted bootstrap state does not default omitted {optional_false}",
        )

    for forbidden in (
        "'token'",
        "'cluster-cidr'",
        "'service-cidr'",
        "'node-ip'",
        "'system-default-registry'",
        "'data-dir'",
    ):
        require(forbidden in preflight, f"extra config does not block {forbidden}")
    require(
        "one control-plane server at a time" in update
        or "one-at-a-time" in update,
        "update does not declare rolling control-plane behavior",
    )
    require(
        "bootstrapControllerVersion" in update,
        "module update does not preserve bootstrap destroy authority",
    )
    require(
        "tasks/apply-rke2-upgrade.yml" in update,
        "update lifecycle does not roll out in-place RKE2 binary upgrades",
    )
    rke2_upgrade_task = read("deploy/playbooks/tasks/apply-rke2-upgrade.yml")
    rke2_upgrade_validator = read("deploy/scripts/validate_rke2_upgrade.py")
    run_launcher = read("deploy/run.sh")
    require(
        "INSPACE_CONFIRM_RKE2_VERSION_SKIP" in rke2_upgrade_task
        and "INSPACE_CONFIRM_RKE2_VERSION_SKIP" in rke2_upgrade_validator
        and "INSPACE_CONFIRM_RKE2_VERSION_SKIP" in run_launcher,
        "RKE2 upgrade lacks a downgrade/minor-skip safety confirmation",
    )
    require(
        "is_downgrade" in rke2_upgrade_validator and "skips_minor" in rke2_upgrade_validator,
        "RKE2 upgrade does not guard against downgrade or multi-minor-version skew",
    )
    rke2_upgrade_script = read("deploy/templates/upgrade-rke2-server.sh")
    require(
        "sha256sum" in rke2_upgrade_script and "systemctl stop rke2-server" in rke2_upgrade_script,
        "RKE2 binary upgrade script does not verify checksums or stop the service before replacing it",
    )
    # The init-time InSpaceCluster record keeps its original RKE2 version (it is
    # bootstrap/destroy authority), so the journal records the version the
    # control plane was last upgraded to and only `update` may move it.
    require(
        "persisted_inspace_cluster.spec.rke2.version == rke2_version" not in load_state
        and "deployment_state.get('rke2Version', persisted_inspace_cluster.spec.rke2.version)" in load_state
        and "deploy_allow_rke2_version_change | default(false) | bool" in load_state
        and "deploy_allow_rke2_version_change: true" in update,
        "deployment journal blocks the documented in-place RKE2 version upgrade",
    )
    require(
        "deploy_recorded_rke2_version != rke2_version" in rke2_upgrade_task
        and "- \"{{ deploy_recorded_rke2_version }}\"" in rke2_upgrade_task
        and "combine({'rke2Version': rke2_version}" in rke2_upgrade_task,
        "RKE2 upgrade is not gated on and does not record the exact journaled RKE2 version",
    )
    # RKE2 release candidates ship the GA hardened kubelet, whose reported
    # version omits the -rcN suffix.
    kubelet_form = "rke2_version | regex_replace('-rc[0-9]+[+]', '+')"
    one_upgrade = read("deploy/playbooks/tasks/upgrade-one-control-plane.yml")
    require(
        kubelet_form in rke2_upgrade_task and "deploy_expected_kubelet_version" in one_upgrade
        and "failed_when: deploy_control_plane_upgraded_version.stdout != rke2_version" not in one_upgrade,
        "RKE2 upgrade readback does not map a release candidate to its kubelet version",
    )
    go_pattern = re.search(
        r"rke2VersionPattern = regexp\.MustCompile\(`([^`]+)`\)",
        read("modules/cloud-provider/api/v1alpha1/types.go"),
    )
    require(
        go_pattern is not None
        and f"rke2_version is match('{go_pattern.group(1).replace(chr(92), chr(92) * 2)}')" in preflight,
        "deploy preflight RKE2 version pattern differs from the InSpaceCluster validator",
    )

    ordered_destroy = (
        "Refuse bootstrap deletion while PVC or PV ownership remains",
        "Delete every LoadBalancer Service while its owning CCM is healthy",
        "Delete every Karpenter NodePool",
        "Wait for all NodeClaims and non-control-plane nodes to disappear",
        "Refuse controller removal while volume attachments remain",
        "Uninstall CCM CSI and Karpenter",
        "Delete only journaled bootstrap-owned infrastructure",
    )
    offsets = [destroy.find(value) for value in ordered_destroy]
    require(all(value >= 0 for value in offsets), "destroy lacks a safety phase")
    require(offsets == sorted(offsets), "destroy safety phases are misordered")
    require(
        "confirm_cluster_name" in destroy
        and "deployment_state.bootstrapControllerVersion" in destroy
        and "--delete" in destroy,
        "destroy lacks confirmation or ledger-bound controller authority",
    )
    for dangerous in (
        "network/network/",
        "delete network",
        "delete floating-ip --all",
        "git clean",
    ):
        require(
            dangerous not in destroy.lower(),
            f"destroy contains broad or unrelated deletion text: {dangerous}",
        )

    for path in (
        "deploy/Dockerfile",
        "deploy/container-entrypoint.sh",
        "deploy/requirements.lock.txt",
        "deploy/run.sh",
        "deploy/scripts/api-tunnel.sh",
        "deploy/scripts/discover_bootstrap.py",
        "deploy/playbooks/init-cluster.yml",
        "deploy/playbooks/update-control-plane.yml",
        "deploy/playbooks/status.yml",
        "deploy/playbooks/tunnel.yml",
        "deploy/playbooks/destroy-cluster.yml",
    ):
        require((ROOT / path).is_file(), f"missing deployment artifact {path}")

    run = read("deploy/run.sh")
    require(
        re.search(r"init \| update \| status \| tunnel \| destroy", run) is not None,
        "launcher does not expose the full lifecycle",
    )
    for fragment in (
        "type=bind,src=$inventory,dst=/run/config/inventory.yml,readonly",
        "type=bind,src=$ssh_dir,dst=$ssh_dir,readonly",
        "type=bind,src=$state_root,dst=$state_root",
        "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock",
        "local/inspace-deploy-runner:$runner_arch-$fingerprint",
    ):
        require(fragment in run, f"containerized launcher lacks {fragment}")
    require(
        "ansible-playbook" not in run,
        "host launcher still depends on a host Ansible installation",
    )
    require(
        "INSPACE_DEPLOY_RUNNER_PLATFORM:-linux/amd64" not in run
        and 'INSPACE_DEPLOY_RUNNER_PLATFORM:-}' in run,
        "deploy runner forces x86 instead of using the management host architecture",
    )
    require(
        "INSPACE_DEPLOY_STATE_ROOT" in preflight
        and "INSPACE_DEPLOY_STATE_ROOT" in container_entrypoint,
        "container state path is not shared with nested Docker safely",
    )
    require(
        "/state/ssh-public-key" in init
        and "src={{ ssh_public_key_file_expanded }}" not in init,
        "nested bootstrap still asks the host daemon to mount a container-only SSH path",
    )
    print("deploy static contracts: ok")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as error:
        print(f"deploy static verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
