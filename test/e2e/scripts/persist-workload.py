#!/usr/bin/env python3
"""Persist exact CSI and Service owner identities as soon as they exist."""

import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import subprocess
import urllib.parse
import uuid

from cloud_identity_journal import record_known_cloud_identities
from durable_io import atomic_write_json


NODE_LOAD_BALANCER_SERVICE_NAMES = (
    "inspace-e2e-node-traefik",
    "inspace-e2e-node-shared-b",
    "inspace-e2e-node-shared-conflict",
    "inspace-e2e-node-dedicated",
)
DATAPATH_NAME_PATTERN = re.compile(r"^inlb-dp-[0-9a-f]{52}$")


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


def node_load_balancer_datapath_name(service: dict) -> str:
    metadata = service.get("metadata", {})
    namespace = metadata.get("namespace")
    name = metadata.get("name")
    uid = metadata.get("uid")
    if not all(isinstance(value, str) and value for value in (namespace, name, uid)):
        raise SystemExit("Node-LB Service lacks a stable namespace, name, or UID")
    identity = hashlib.sha256(f"{namespace}\0{name}\0{uid}".encode()).hexdigest()[:52]
    return "inlb-dp-" + identity


def recover_nodeclaim_cloud_identities(kubeconfig: str) -> tuple[list[str], list[str]]:
    claims = kubectl(kubeconfig, "get", "nodeclaims")
    if claims is None:
        return [], []
    items = claims.get("items")
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        raise SystemExit("NodeClaim recovery inventory is malformed")
    location = os.environ["INSPACE_LOCATION"]
    vm_uuids = []
    public_addresses = []
    for claim in items:
        status = claim.get("status", {})
        if not isinstance(status, dict):
            raise SystemExit("NodeClaim recovery status is malformed")
        provider_id = status.get("providerID")
        if provider_id in (None, ""):
            continue
        if not isinstance(provider_id, str):
            raise SystemExit("NodeClaim recovery providerID is malformed")
        parsed = urllib.parse.urlsplit(provider_id)
        if (
            parsed.scheme != "inspace"
            or parsed.netloc != location
            or parsed.query
            or parsed.fragment
            or not parsed.path.startswith("/")
            or "/" in parsed.path[1:]
        ):
            raise SystemExit("NodeClaim recovery providerID is not canonical")
        vm_uuid = parsed.path[1:]
        try:
            canonical_uuid = str(uuid.UUID(vm_uuid))
        except ValueError as error:
            raise SystemExit("NodeClaim recovery providerID lacks a VM UUID") from error
        if canonical_uuid != vm_uuid:
            raise SystemExit("NodeClaim recovery VM UUID is not canonical")
        vm_uuids.append(vm_uuid)

        node_name = status.get("nodeName")
        if node_name in (None, ""):
            continue
        if not isinstance(node_name, str):
            raise SystemExit("NodeClaim recovery nodeName is malformed")
        node = kubectl(kubeconfig, "get", "node", node_name)
        if node is None:
            continue
        if not isinstance(node, dict) or node.get("spec", {}).get(
            "providerID"
        ) != provider_id:
            raise SystemExit(
                "NodeClaim recovery Node does not bind its exact providerID"
            )
        external = [
            address.get("address")
            for address in node.get("status", {}).get("addresses", [])
            if isinstance(address, dict) and address.get("type") == "ExternalIP"
        ]
        if len(external) > 1:
            raise SystemExit("NodeClaim recovery Node has multiple ExternalIPs")
        if external:
            try:
                parsed_address = ipaddress.ip_address(external[0])
            except ValueError as error:
                raise SystemExit(
                    "NodeClaim recovery ExternalIP is malformed"
                ) from error
            if (
                parsed_address.version != 4
                or not parsed_address.is_global
                or str(parsed_address) != external[0]
            ):
                raise SystemExit(
                    "NodeClaim recovery ExternalIP is not canonical public IPv4"
                )
            public_addresses.append(external[0])
    if len(vm_uuids) != len(set(vm_uuids)):
        raise SystemExit("NodeClaim recovery repeats a VM provider identity")
    if len(public_addresses) != len(set(public_addresses)):
        raise SystemExit("NodeClaim recovery repeats an ExternalIP")
    return sorted(vm_uuids), sorted(public_addresses)


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
    raw_datapath_names = state.get("nodeLoadBalancerDatapathServiceNames", [])
    if not isinstance(raw_datapath_names, list) or any(
        not isinstance(name, str) or DATAPATH_NAME_PATTERN.fullmatch(name) is None
        for name in raw_datapath_names
    ):
        raise SystemExit("Node-LB datapath Service journal is invalid")
    node_lb_names = set(raw_node_lb_names)
    datapath_names = set(raw_datapath_names)
    for service_name in NODE_LOAD_BALANCER_SERVICE_NAMES:
        service = kubectl(args.kubeconfig, "-n", "default", "get", "service", service_name)
        if not service:
            continue
        uid = service.get("metadata", {}).get("uid")
        if not isinstance(uid, str) or not uid:
            raise SystemExit(f"Service/{service_name} lacks a stable UID")
        node_lb_names.add(f"k8s-{sha16(state['clusterName'])}-{sha16(uid)}")
        datapath_names.add(node_load_balancer_datapath_name(service))
    state["nodeLoadBalancerForbiddenLoadBalancerNames"] = sorted(node_lb_names)
    state["nodeLoadBalancerDatapathServiceNames"] = sorted(datapath_names)

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
    vm_uuids, public_addresses = recover_nodeclaim_cloud_identities(
        args.kubeconfig
    )
    atomic_write_json(path, state)
    record_known_cloud_identities(
        path,
        state,
        vm_uuids=vm_uuids,
        floating_ip_addresses=public_addresses,
    )


if __name__ == "__main__":
    main()
