#!/usr/bin/env python3
"""Persist exact CSI and Service owner identities as soon as they exist."""

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile


NODE_LOAD_BALANCER_SERVICE_NAMES = (
    "inspace-e2e-node-traefik",
    "inspace-e2e-node-shared-a",  # pre-release E2E rename recovery
    "inspace-e2e-node-shared-b",
    "inspace-e2e-node-shared-conflict",
    "inspace-e2e-node-dedicated",
)


def kubectl(kubeconfig: str, *args: str):
    command = ["kubectl", "--kubeconfig", kubeconfig, *args, "--ignore-not-found=true", "-o", "json"]
    process = subprocess.run(command, check=False, capture_output=True, text=True, timeout=60)
    if process.returncode != 0:
        message = process.stderr.strip() or "kubectl returned no error text"
        raise RuntimeError(f"kubectl ownership lookup failed: {message}")
    if not process.stdout.strip():
        return None
    return json.loads(process.stdout)


def sha16(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def atomic_write(path: pathlib.Path, value) -> None:
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--kubeconfig", required=True)
    args = parser.parse_args()
    path = pathlib.Path(args.state)
    state = json.loads(path.read_text(encoding="utf-8"))

    private_load_balancers = set(state.get("privateServiceLoadBalancerNames", []))
    private_floating_ips = set(state.get("privateServiceFloatingIPNames", []))
    private_service_vips = set(state.get("privateServiceVIPs", []))
    for service_name in ("inspace-e2e-web", "inspace-e2e-private-a", "inspace-e2e-private-b"):
        service = kubectl(args.kubeconfig, "-n", "default", "get", "service", service_name)
        if not service:
            continue
        uid = service["metadata"]["uid"]
        lb_name = f"k8s-{sha16(state['clusterName'])}-{sha16(uid)}"
        if service_name == "inspace-e2e-web":
            state.update({
                "serviceUID": uid,
                "serviceLoadBalancerName": lb_name,
                "serviceFloatingIPName": lb_name + "-ip",
            })
            continue
        private_load_balancers.add(lb_name)
        private_floating_ips.add(lb_name + "-ip")
        for ingress in service.get("status", {}).get("loadBalancer", {}).get("ingress", []):
            if ingress.get("ip"):
                private_service_vips.add(ingress["ip"])
    state["privateServiceLoadBalancerNames"] = sorted(private_load_balancers)
    state["privateServiceFloatingIPNames"] = sorted(private_floating_ips)
    state["privateServiceVIPs"] = sorted(private_service_vips)

    raw_node_lb_names = state.get("nodeLoadBalancerForbiddenLoadBalancerNames", [])
    if not isinstance(raw_node_lb_names, list) or any(
        not isinstance(name, str) or not name for name in raw_node_lb_names
    ):
        raise SystemExit("Node-LB NLB deny journal is invalid")
    node_lb_names = set(raw_node_lb_names)
    for service_name in NODE_LOAD_BALANCER_SERVICE_NAMES:
        service = kubectl(args.kubeconfig, "-n", "default", "get", "service", service_name)
        if not service:
            continue
        uid = service.get("metadata", {}).get("uid")
        if not isinstance(uid, str) or not uid:
            raise SystemExit(f"Service/{service_name} lacks a stable UID")
        node_lb_names.add(f"k8s-{sha16(state['clusterName'])}-{sha16(uid)}")
    state["nodeLoadBalancerForbiddenLoadBalancerNames"] = sorted(node_lb_names)

    pvc = kubectl(args.kubeconfig, "-n", "default", "get", "pvc", "inspace-e2e-rwo")
    if pvc:
        uid = pvc["metadata"]["uid"]
        state.update({"pvcUID": uid, "pvcDiskName": "pvc-" + uid})
        pv_name = pvc.get("spec", {}).get("volumeName")
        if pv_name:
            pv = kubectl(args.kubeconfig, "get", "pv", pv_name)
            if pv:
                handle = pv.get("spec", {}).get("csi", {}).get("volumeHandle", "")
                if handle:
                    state.update({
                        "pvName": pv_name,
                        "volumeHandle": handle,
                        "diskUUID": handle.rsplit("/", 1)[-1],
                    })
    atomic_write(path, state)


if __name__ == "__main__":
    main()
