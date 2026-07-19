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
    for ignored in ("deploy/inventory.yml", "deploy/inventory/", "deploy/.state/"):
        require(ignored in gitignore, f"missing Git exclusion {ignored}")
        require(ignored in dockerignore, f"missing Docker exclusion {ignored}")
    require(
        "ubuntu:26.04@sha256:" in dockerfile
        and "docker:29.4.0-cli@sha256:" in dockerfile,
        "deploy runner base or Docker CLI image is not digest locked",
    )
    require(
        "ansible-core==2.21.2" in dependency_lock
        and all(
            line == "" or line.startswith("#") or re.search(r"^[A-Za-z0-9_.-]+==[^=]+$", line)
            for line in dependency_lock.splitlines()
        ),
        "deploy Python dependency lock contains an unpinned requirement",
    )
    require(
        "KUBECTL_VERSION=v1.35.6" in dockerfile
        and "alpine/helm:3.18.4@sha256:" in dockerfile
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
