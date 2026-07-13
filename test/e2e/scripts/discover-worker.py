#!/usr/bin/env python3
"""Bind a Ready Karpenter Node to one exact InSpace VM, VPC, and public IP."""

import argparse
import ipaddress
import json
import os
import pathlib
import re
import ssl
import tempfile
import urllib.parse
import urllib.request


def api_get(path: str):
    base = os.environ["INSPACE_API_URL"].rstrip("/")
    location = os.environ["INSPACE_LOCATION"]
    request = urllib.request.Request(
        f"{base}/v1/{location}/{path}",
        headers={"apikey": os.environ["INSPACE_API_TOKEN"], "User-Agent": "inspace-rke2-e2e-worker/1"},
    )
    with urllib.request.urlopen(request, timeout=60, context=ssl.create_default_context()) as response:
        return json.load(response)


def description(vm):
    try:
        result = json.loads(vm.get("description", "{}"))
        return result if isinstance(result, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}


VM_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def canonical_worker_vm_detail(listed_vms, node_name: str, nodepool: str, getter=api_get):
    """Resolve one exact sparse list row to its authoritative VM detail."""
    if not isinstance(node_name, str) or not node_name.startswith(nodepool + "-"):
        raise SystemExit("Ready Karpenter Node name is outside the expected NodePool identity")
    matches = []
    for summary in listed_vms:
        if not isinstance(summary, dict):
            raise SystemExit("worker VM list contained a non-object record")
        if summary.get("name") == node_name:
            matches.append(summary)
    if len(matches) != 1:
        raise SystemExit("expected one exact cloud VM list identity for the Ready Karpenter Node")
    vm_uuid = matches[0].get("uuid")
    if not isinstance(vm_uuid, str) or not VM_UUID_PATTERN.fullmatch(vm_uuid):
        raise SystemExit("worker VM list identity lacks a valid UUID")
    query = urllib.parse.urlencode({"uuid": vm_uuid})
    detail = getter(f"user-resource/vm?{query}")
    if not isinstance(detail, dict) or detail.get("uuid") != vm_uuid or detail.get("name") != node_name:
        raise SystemExit("authoritative worker VM detail does not match the list UUID and Node name")
    return detail


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
    parser.add_argument("--node", required=True)
    args = parser.parse_args()
    state_path = pathlib.Path(args.state)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    node = json.loads(args.node)
    cluster = state["clusterName"]
    nodepool = state["nodePoolName"]
    location = os.environ["INSPACE_LOCATION"]

    vms = api_get("user-resource/vm/list")
    vm = canonical_worker_vm_detail(vms, node.get("name"), nodepool)
    vm_uuid = vm["uuid"]
    record = description(vm)
    amd_pool_uuid = os.environ["INSPACE_AMD_HOST_POOL_UUID"]
    if (
        record.get("cluster") != cluster
        or record.get("nodeClaim") != node.get("name")
        or not record.get("floatingIPName")
        or record.get("hostClass") != "amd-epyc"
        or record.get("hostPoolUUID") != amd_pool_uuid
        or vm.get("designated_pool_uuid") != amd_pool_uuid
    ):
        raise SystemExit("worker must use the exact configured AMD EPYC host pool and persisted ownership")
    if node.get("providerID") != f"inspace://{location}/{vm_uuid}":
        raise SystemExit("Node providerID does not bind to the discovered VM UUID")

    internal_ips = node.get("internalIPs", [])
    if not isinstance(internal_ips, list) or len(internal_ips) != 1:
        raise SystemExit("worker must expose exactly one InternalIP")
    internal_ip = ipaddress.ip_address(internal_ips[0])
    if internal_ip.version != 4 or not internal_ip.is_private:
        raise SystemExit("worker InternalIP must be RFC1918 IPv4")

    network_uuid = os.environ["INSPACE_NETWORK_UUID"]
    network = api_get(f"network/network/{network_uuid}")
    if not isinstance(network, dict) or network.get("uuid") != network_uuid:
        raise SystemExit("configured VPC lookup was not authoritative")
    if list(network.get("vm_uuids", [])).count(vm_uuid) != 1:
        raise SystemExit("worker VM is not an exact member of the configured VPC")
    subnet = ipaddress.ip_network(network["subnet"], strict=False)
    if internal_ip not in subnet:
        raise SystemExit("worker InternalIP is outside the configured VPC subnet")
    try:
        vm_private_ip = ipaddress.ip_address(str(vm.get("private_ipv4")))
    except ValueError as error:
        raise SystemExit("worker VM must expose one authoritative private IPv4") from error
    if (
        vm_private_ip.version != 4
        or not vm_private_ip.is_private
        or str(vm_private_ip) != str(vm.get("private_ipv4"))
        or vm_private_ip != internal_ip
    ):
        raise SystemExit("worker VM private IPv4 must exactly equal the Node InternalIP")
    pool_start = ipaddress.ip_address(os.environ["INSPACE_PRIVATE_LOAD_BALANCER_POOL_START"])
    pool_stop = ipaddress.ip_address(os.environ["INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP"])
    control_plane_vip = ipaddress.ip_address(state["virtualIPv4"])
    if internal_ip == control_plane_vip:
        raise SystemExit("worker InternalIP collides with the private control-plane VIP")
    if int(pool_start) <= int(internal_ip) <= int(pool_stop):
        raise SystemExit("worker InternalIP collides with the operator-reserved private Service VIP range")

    all_firewalls = api_get("network/firewalls")
    firewalls = [firewall for firewall in all_firewalls if firewall.get("uuid") == state.get("firewallUUID")]
    if len(firewalls) != 1:
        raise SystemExit("expected the exact managed node firewall for the worker")
    worker_firewalls = [
        firewall for firewall in all_firewalls
        if any(
            item.get("resource_type") == "vm" and item.get("resource_uuid") == vm_uuid
            for item in firewall.get("resources_assigned", [])
        )
    ]
    if len(worker_firewalls) != 1 or worker_firewalls[0].get("uuid") != state.get("firewallUUID"):
        raise SystemExit("worker must be attached to exactly the intended managed cloud firewall")
    assignments = firewalls[0].get("resources_assigned", [])
    expected_firewall_vms = set(state.get("controlPlaneVMs", [])) | {vm_uuid}
    if (
        len(assignments) != 4
        or any(item.get("resource_type") != "vm" for item in assignments)
        or {item.get("resource_uuid") for item in assignments} != expected_firewall_vms
    ):
        raise SystemExit("managed node firewall must protect exactly three control planes and the worker")

    fip_name = record["floatingIPName"]
    all_addresses = [
        ip for ip in api_get("network/ip_addresses")
        if not ip.get("is_deleted", False)
    ]
    addresses = [
        ip for ip in all_addresses
        if ip.get("name") == fip_name
        and ip.get("assigned_to") == vm_uuid
        and ip.get("assigned_to_resource_type") == "virtual_machine"
        and ip.get("enabled") is True
        and ip.get("is_virtual") is False
        and ip.get("type") == "public"
    ]
    if len(addresses) != 1:
        raise SystemExit("worker must own exactly one expected floating IPv4")
    if len([ip for ip in all_addresses if ip.get("assigned_to") == vm_uuid]) != 1:
        raise SystemExit("worker must not have an additional or foreign-named floating IPv4")
    public_ip = ipaddress.ip_address(addresses[0]["address"])
    if public_ip.version != 4 or not public_ip.is_global or public_ip.is_loopback or public_ip.is_multicast:
        raise SystemExit("worker floating address is not public IPv4")
    if addresses[0].get("assigned_to_private_ip") and str(addresses[0]["assigned_to_private_ip"]) != str(internal_ip):
        raise SystemExit("worker FIP private-address readback disagrees with the Node InternalIP")
    if vm.get("public_ipv4"):
        try:
            vm_public_ip = ipaddress.ip_address(str(vm["public_ipv4"]))
        except ValueError as error:
            raise SystemExit("worker VM public IPv4 readback is malformed") from error
        if vm_public_ip != public_ip:
            raise SystemExit("worker VM public IPv4 must equal its exact assigned FIP")

    worker = {
        "uuid": vm_uuid,
        "name": vm["name"],
        "fip": fip_name,
        "publicIPv4": str(public_ip),
        "internalIPv4": str(internal_ip),
    }
    state["workerVMs"] = [worker]
    state["workerNode"] = node["name"]
    state["workerPublicIPv4"] = str(public_ip)
    atomic_write(state_path, state)
    print(json.dumps(worker, sort_keys=True))


if __name__ == "__main__":
    main()
