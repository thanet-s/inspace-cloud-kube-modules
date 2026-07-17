#!/usr/bin/env python3
"""Fail-closed audit of deterministic cloud resources owned by one E2E run."""

import argparse
import ipaddress
import json
import os
import pathlib
import re
import time
import urllib.parse
import uuid

from cloud_identity_journal import record_known_cloud_identities
from strict_inspace_api import StrictInSpaceAPI, location_api_get


def api_get(path: str):
    return location_api_get(path, user_agent="inspace-rke2-e2e-audit/2")


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


def _journal_string_set(state: dict, key: str) -> set[str]:
    values = state.get(key, [])
    if not isinstance(values, list) or any(
        not isinstance(value, str) or not value for value in values
    ):
        raise SystemExit(f"ownership journal {key} must contain unique strings")
    if len(values) != len(set(values)):
        raise SystemExit(f"ownership journal {key} contains duplicates")
    return set(values)


def _bootstrap_vm_owned(
    vm: dict,
    *,
    owner: str,
    control_plane_names: set[str],
    bastion_vm_names: set[str],
) -> bool:
    name = vm.get("name")
    description = vm.get("description")
    if not isinstance(name, str) or not isinstance(description, str):
        return False
    owner_expression = re.escape(owner)
    if name in control_plane_names:
        return (
            re.fullmatch(
                rf"inspace-rke2-cp/v[0-9]+ owner={owner_expression} "
                rf"slot=[0-2] spec=[0-9a-f]{{64}}",
                description,
            )
            is not None
        )
    if name in bastion_vm_names:
        return (
            re.fullmatch(
                rf"inspace-rke2-bastion/v[0-9]+ owner={owner_expression} "
                rf"spec=[0-9a-f]{{64}}",
                description,
            )
            is not None
        )
    return False


def _karpenter_vm_ownership(
    vm: dict,
    *,
    cluster: str,
    billing_account: int,
    network_uuid: str,
    worker_vm_names: set[str],
    worker_vm_prefix: str,
) -> dict | None:
    name = vm.get("name")
    description = parse_description(vm.get("description"))
    if not isinstance(name, str):
        return None
    # The prefix and journaled names are discovery hints only. Ownership still
    # requires the complete immutable Karpenter description, so a foreign VM
    # with a similar human-readable name cannot enter the durable journal.
    hinted = (
        name in worker_vm_names
        or name.startswith(worker_vm_prefix)
        or description.get("cluster") == cluster
    )
    if not hinted:
        return None
    if description.get("schema") not in {
        "karpenter.inspace.cloud/v1",
        "karpenter.inspace.cloud/v2",
        "karpenter.inspace.cloud/v3",
    }:
        return None
    if (
        description.get("cluster") != cluster
        or description.get("vmName") not in (None, "", name)
        or description.get("billingAccountID") != billing_account
        or description.get("networkUUID") != network_uuid
    ):
        return None
    if not isinstance(description.get("nodeClaim"), str) or not description[
        "nodeClaim"
    ]:
        return None
    floating_ip_name = description.get("floatingIPName")
    if not isinstance(floating_ip_name, str) or not floating_ip_name:
        return None
    return description


def audit_once(state: dict, owner: str, cluster: str, nodepool: str) -> dict:
    service_lb = state.get("serviceLoadBalancerName", "")
    service_ip = state.get("serviceFloatingIPName", "")
    if not isinstance(service_lb, str) or not isinstance(service_ip, str):
        raise SystemExit("ownership journal Service cloud names must be strings")
    service_lbs = (
        {service_lb}
        | _journal_string_set(state, "privateServiceLoadBalancerNames")
        | _journal_string_set(state, "nodeLoadBalancerForbiddenLoadBalancerNames")
    ) - {""}
    service_ips = (
        {service_ip}
        | _journal_string_set(state, "privateServiceFloatingIPNames")
    ) - {""}
    disk_uuid = state.get("diskUUID", "")
    disk_name = state.get("pvcDiskName", "")
    if not isinstance(disk_uuid, str) or not isinstance(disk_name, str):
        raise SystemExit("ownership journal disk identities must be strings")
    billing_account = int(os.environ["INSPACE_BILLING_ACCOUNT_ID"])
    network_uuid = os.environ["INSPACE_NETWORK_UUID"]
    exact_identities = known_exact_identities(state)
    known_vm_ids = set(exact_identities["vms"])
    known_disk_ids = set(exact_identities["disks"])
    known_load_balancer_ids = set(exact_identities["loadBalancers"])
    known_floating_ip_addresses = set(exact_identities["floatingIPs"])
    bootstrap_fip_names = {
        f"{cluster}-bastion-ip",
        *(f"{cluster}-cp{slot}-ip" for slot in range(3)),
    }
    control_plane_names = {
        str(item.get("name")) for item in state.get("controlPlanes", [])
        if isinstance(item, dict) and item.get("name")
    }
    if not control_plane_names:
        control_plane_names = {f"{cluster}-cp{slot}" for slot in range(3)}
    bastion_vm_names = {
        f"{cluster}-bastion",
        f"rke2-{owner}-bastion",
    }
    worker_vm_names = {
        str(item.get("name"))
        for item in state.get("workerVMs", [])
        if isinstance(item, dict) and item.get("name")
    }
    worker_fip_names = {
        str(item.get("fip"))
        for item in state.get("workerVMs", [])
        if isinstance(item, dict) and item.get("fip")
    }
    worker_vm_prefix = f"{cluster}-karp-{nodepool}-"
    worker_fip_prefix = f"karpenter-{nodepool}-"
    all_vms = list(active_resources("user-resource/vm/list"))
    karpenter_records = {
        vm.get("uuid"): record
        for vm in all_vms
        if (
            record := _karpenter_vm_ownership(
                vm,
                cluster=cluster,
                billing_account=billing_account,
                network_uuid=network_uuid,
                worker_vm_names=worker_vm_names,
                worker_vm_prefix=worker_vm_prefix,
            )
        )
        is not None
    }
    worker_fip_names.update(
        str(record["floatingIPName"]) for record in karpenter_records.values()
    )
    vms = [
        {"uuid": vm.get("uuid"), "name": vm.get("name")}
        for vm in all_vms
        if vm.get("uuid") in known_vm_ids
        or vm.get("uuid") in karpenter_records
        or vm.get("name") in worker_vm_names
        or _bootstrap_vm_owned(
            vm,
            owner=owner,
            control_plane_names=control_plane_names,
            bastion_vm_names=bastion_vm_names,
        )
    ]
    owned_vm_ids = {item["uuid"] for item in vms}

    all_load_balancers = list(active_resources("network/load_balancers"))
    load_balancers = [
        {
            "uuid": lb.get("uuid"),
            "name": lb.get("display_name"),
            "privateAddress": lb.get("private_address"),
        }
        for lb in all_load_balancers
        if lb.get("uuid") in known_load_balancer_ids
        or (
            lb.get("display_name") in service_lbs
            and lb.get("network_uuid") == network_uuid
            and lb.get("billing_account_id") == billing_account
        )
    ]
    owned_load_balancer_ids = {item["uuid"] for item in load_balancers}

    all_floating_ips = list(active_resources("network/ip_addresses"))
    floating_ips = [
        {
            "address": ip.get("address"),
            "name": ip.get("name"),
            "assigned_to": ip.get("assigned_to"),
        }
        for ip in all_floating_ips
        if ip.get("address") in known_floating_ip_addresses
        or (
            ip.get("billing_account_id") == billing_account
            and ip.get("assigned_to")
            in (owned_vm_ids | owned_load_balancer_ids)
        )
        or (
            ip.get("billing_account_id") == billing_account
            and (
                ip.get("name") in bootstrap_fip_names
                or ip.get("name") in service_ips
                or ip.get("name") in worker_fip_names
            )
        )
    ]

    all_firewalls = list(active_resources("network/firewalls"))
    firewalls = [
        {"uuid": fw.get("uuid"), "name": fw.get("display_name", fw.get("name"))}
        for fw in all_firewalls
        if fw.get("display_name", fw.get("name")) in {
            f"{cluster}-nodes-{owner}",
            f"{cluster}-bastion-{owner}",
            f"rke2-{owner}-nodes",
            f"rke2-{owner}-bastion",
            f"k3s-{owner}-nodes",
        }
        and fw.get("billing_account_id") == billing_account
    ]

    all_disks = list(active_resources("storage/disks"))
    disks = [
        {"uuid": disk.get("uuid"), "name": disk.get("display_name")}
        for disk in all_disks
        if disk.get("uuid") in known_disk_ids
        or (disk_uuid and disk.get("uuid") == disk_uuid)
        or (
            disk_name
            and disk.get("display_name") == disk_name
            and disk.get("billing_account_id") == billing_account
        )
    ]
    result = {
        "vms": sorted(vms, key=lambda item: (item["uuid"], item["name"])),
        "firewalls": sorted(
            firewalls, key=lambda item: (item["uuid"], item["name"])
        ),
        "floatingIPs": sorted(
            floating_ips, key=lambda item: (item["address"], item["name"])
        ),
        "loadBalancers": sorted(
            load_balancers, key=lambda item: (item["uuid"], item["name"])
        ),
        "disks": sorted(disks, key=lambda item: (item["uuid"], item["name"])),
    }
    result["count"] = sum(len(value) for value in result.values())
    # Keep the historical prefix visible in this audit contract. Exact worker
    # FIP ownership is derived from the immutable VM description or journal,
    # never from this broad prefix alone.
    _ = worker_fip_prefix
    return result


def _canonical_uuid(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SystemExit(f"ownership journal {label} is not a UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise SystemExit(f"ownership journal {label} is not a UUID") from error
    if str(parsed) != value:
        raise SystemExit(f"ownership journal {label} is not canonical")
    return value


def _canonical_ip(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SystemExit(f"ownership journal {label} is not an IP address")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as error:
        raise SystemExit(f"ownership journal {label} is not an IP address") from error
    if str(parsed) != value:
        raise SystemExit(f"ownership journal {label} is not canonical")
    return value


def known_exact_identities(state: dict) -> dict[str, list[str]]:
    identities = {"vms": [], "disks": [], "loadBalancers": [], "floatingIPs": []}

    def add(kind: str, value: object, label: str, validator) -> None:
        if value in (None, ""):
            return
        identities[kind].append(validator(value, label))

    def add_list(kind: str, key: str, validator) -> None:
        values = state.get(key, [])
        if not isinstance(values, list):
            raise SystemExit(f"ownership journal {key} must be an array")
        for index, value in enumerate(values):
            add(kind, value, f"{key}[{index}]", validator)

    add("vms", state.get("bastionVMUUID"), "bastionVMUUID", _canonical_uuid)
    add_list("vms", "controlPlaneVMs", _canonical_uuid)
    add_list("floatingIPs", "controlPlanePublicIPv4s", _canonical_ip)
    add(
        "floatingIPs",
        state.get("workerPublicIPv4"),
        "workerPublicIPv4",
        _canonical_ip,
    )
    for index, item in enumerate(state.get("controlPlanes", [])):
        if not isinstance(item, dict):
            raise SystemExit("ownership journal controlPlanes contains a non-object")
        add("vms", item.get("uuid"), f"controlPlanes[{index}].uuid", _canonical_uuid)
        add(
            "floatingIPs",
            item.get("publicIPv4"),
            f"controlPlanes[{index}].publicIPv4",
            _canonical_ip,
        )
    for index, item in enumerate(state.get("workerVMs", [])):
        if not isinstance(item, dict):
            raise SystemExit("ownership journal workerVMs contains a non-object")
        add("vms", item.get("uuid"), f"workerVMs[{index}].uuid", _canonical_uuid)
        add(
            "floatingIPs",
            item.get("publicIPv4"),
            f"workerVMs[{index}].publicIPv4",
            _canonical_ip,
        )
    add("disks", state.get("diskUUID"), "diskUUID", _canonical_uuid)
    add(
        "floatingIPs",
        state.get("bastionPublicIPv4"),
        "bastionPublicIPv4",
        _canonical_ip,
    )
    for key, kind, validator in (
        ("knownVMUUIDs", "vms", _canonical_uuid),
        ("knownDiskUUIDs", "disks", _canonical_uuid),
        ("knownLoadBalancerUUIDs", "loadBalancers", _canonical_uuid),
        ("knownFloatingIPAddresses", "floatingIPs", _canonical_ip),
    ):
        add_list(kind, key, validator)
    for kind, values in identities.items():
        if len(values) != len(set(values)):
            # The same identity can be recorded through two journal paths.  It
            # is still one exact object and must be read exactly once per pass.
            identities[kind] = sorted(set(values))
        else:
            identities[kind] = sorted(values)
    return identities


def corroborate_exact_absence(state: dict) -> None:
    api = StrictInSpaceAPI.from_environment(
        user_agent="inspace-rke2-e2e-final-exact-audit/1"
    )
    location = os.environ["INSPACE_LOCATION"]
    identities = known_exact_identities(state)
    paths = {
        "vms": lambda identity: "user-resource/vm?"
        + urllib.parse.urlencode({"uuid": identity}),
        "disks": lambda identity: f"storage/disks/{identity}",
        "loadBalancers": lambda identity: f"network/load_balancers/{identity}",
        "floatingIPs": lambda identity: "network/ip_addresses/"
        + urllib.parse.quote(identity, safe=".:"),
    }
    for kind, values in identities.items():
        for identity in values:
            if not api.exact_absent(paths[kind](identity), location=location):
                raise SystemExit(
                    f"journaled {kind} identity remains present after list audit"
                )


def stable_audit(
    state: dict,
    owner: str,
    cluster: str,
    nodepool: str,
    *,
    audit_reader=audit_once,
    read_count: int = 3,
    delay_seconds: float = 1.0,
    sleeper=time.sleep,
    exact_absence_reader=corroborate_exact_absence,
) -> dict:
    if read_count < 3:
        raise ValueError("a final ownership proof requires at least three reads")
    if delay_seconds < 0:
        raise ValueError("ownership audit delay cannot be negative")
    snapshots = []
    for index in range(read_count):
        snapshot = audit_reader(state, owner, cluster, nodepool)
        if snapshot.get("count") == 0:
            exact_absence_reader(state)
        snapshots.append(snapshot)
        if index + 1 < read_count:
            sleeper(delay_seconds)
    anchor = snapshots[0]
    if any(snapshot != anchor for snapshot in snapshots[1:]):
        raise SystemExit(
            "deterministic ownership audit changed across three spaced strict reads"
        )
    anchor = dict(anchor)
    anchor["strictReadCount"] = read_count
    return anchor


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

    result = stable_audit(
        state,
        args.owner,
        args.cluster,
        args.nodepool,
    )
    record_known_cloud_identities(
        state_path,
        state,
        vm_uuids=(item["uuid"] for item in result["vms"]),
        disk_uuids=(item["uuid"] for item in result["disks"]),
        load_balancer_uuids=(
            item["uuid"] for item in result["loadBalancers"]
        ),
        floating_ip_addresses=(
            item["address"] for item in result["floatingIPs"]
        ),
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
