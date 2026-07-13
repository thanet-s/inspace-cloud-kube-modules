#!/usr/bin/env python3
"""Fail-closed audit of deterministic cloud resources owned by one E2E run."""

import argparse
import json
import os
import pathlib
import ssl
import urllib.request


def api_get(path: str):
    base = os.environ["INSPACE_API_URL"].rstrip("/")
    location = os.environ["INSPACE_LOCATION"]
    request = urllib.request.Request(
        f"{base}/v1/{location}/{path}",
        headers={"apikey": os.environ["INSPACE_API_TOKEN"], "User-Agent": "inspace-rke2-e2e-audit/1"},
    )
    with urllib.request.urlopen(request, timeout=60, context=ssl.create_default_context()) as response:
        value = json.load(response)
    if not isinstance(value, list):
        raise RuntimeError(f"{path} did not return a list")
    return value


def parse_description(value):
    if not isinstance(value, str):
        return {}
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def active_resources(path: str):
    for item in api_get(path):
        if not isinstance(item, dict):
            raise SystemExit(f"{path} returned a non-object resource item")
        if item.get("is_deleted") is True or str(item.get("status", "")).lower() == "deleted":
            continue
        yield item


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--nodepool", required=True)
    args = parser.parse_args()

    state_path = pathlib.Path(args.state)
    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
    elif os.getenv("E2E_AUDIT_ALLOW_MISSING_STATE") == "true":
        state = {}
    else:
        raise SystemExit("ownership journal is missing")
    if not isinstance(state, dict):
        raise SystemExit("ownership journal must contain an object")

    service_lb = state.get("serviceLoadBalancerName", "")
    service_ip = state.get("serviceFloatingIPName", "")
    service_lbs = {service_lb, *state.get("privateServiceLoadBalancerNames", [])} - {""}
    service_ips = {service_ip, *state.get("privateServiceFloatingIPNames", [])} - {""}
    disk_uuid = state.get("diskUUID", "")
    disk_name = state.get("pvcDiskName", "")
    control_prefixes = (f"rke2-{args.owner}-", f"k3s-{args.owner}-")
    bootstrap_fip_names = {
        f"{args.cluster}-bastion-ip",
        *(f"{args.cluster}-cp{slot}-ip" for slot in range(3)),
    }
    control_plane_names = {
        str(item.get("name")) for item in state.get("controlPlanes", [])
        if isinstance(item, dict) and item.get("name")
    }
    if not control_plane_names:
        control_plane_names = {f"{args.cluster}-cp{slot}" for slot in range(3)}
    bastion_vm_names = {
        f"{args.cluster}-bastion",
        f"rke2-{args.owner}-bastion",
    }
    worker_vm_names = {
        str(item.get("name")) for item in state.get("workerVMs", [])
        if isinstance(item, dict) and item.get("name")
    }
    worker_fip_names = {
        str(item.get("fip")) for item in state.get("workerVMs", [])
        if isinstance(item, dict) and item.get("fip")
    }
    worker_vm_prefix = f"{args.cluster}-karp-{args.nodepool}-"
    worker_fip_prefix = f"karpenter-{args.nodepool}-"

    vms = [
        {"uuid": vm.get("uuid"), "name": vm.get("name")}
        for vm in active_resources("user-resource/vm/list")
        if vm.get("name") in control_plane_names
        or vm.get("name") in bastion_vm_names
        or vm.get("name") in worker_vm_names
        or str(vm.get("name", "")).startswith(control_prefixes)
        or str(vm.get("name", "")).startswith(worker_vm_prefix)
        or str(vm.get("name", "")).startswith(args.nodepool + "-")
        or parse_description(vm.get("description")).get("cluster") == args.cluster
    ]
    firewalls = [
        {"uuid": fw.get("uuid"), "name": fw.get("display_name", fw.get("name"))}
        for fw in active_resources("network/firewalls")
        if fw.get("display_name", fw.get("name")) in {
            f"{args.cluster}-nodes-{args.owner}",
            f"{args.cluster}-bastion-{args.owner}",
            f"rke2-{args.owner}-nodes",
            f"rke2-{args.owner}-bastion",
            f"k3s-{args.owner}-nodes",
        }
    ]
    floating_ips = [
        {"address": ip.get("address"), "name": ip.get("name"), "assigned_to": ip.get("assigned_to")}
        for ip in active_resources("network/ip_addresses")
        if ip.get("name") in bootstrap_fip_names
        or str(ip.get("name", "")).startswith(control_prefixes)
        or ip.get("name") in worker_fip_names
        or str(ip.get("name", "")).startswith(worker_fip_prefix)
        or str(ip.get("name", "")).startswith(args.nodepool + "-")
        or ip.get("name") in service_ips
    ]
    load_balancers = [
        {"uuid": lb.get("uuid"), "name": lb.get("display_name"), "privateAddress": lb.get("private_address")}
        for lb in active_resources("network/load_balancers")
        if lb.get("display_name") in {
            f"rke2-{args.owner}-api",
            f"rke2-{args.owner}-registration",
            f"k3s-{args.owner}-api",
        } | service_lbs
    ]
    disks = [
        {"uuid": disk.get("uuid"), "name": disk.get("display_name")}
        for disk in active_resources("storage/disks")
        if (disk_uuid and disk.get("uuid") == disk_uuid)
        or (disk_name and disk.get("display_name") == disk_name)
    ]
    result = {
        "vms": vms,
        "firewalls": firewalls,
        "floatingIPs": floating_ips,
        "loadBalancers": load_balancers,
        "disks": disks,
    }
    result["count"] = sum(len(value) for value in result.values())
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
