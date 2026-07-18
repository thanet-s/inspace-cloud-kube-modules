#!/usr/bin/env python3
"""Bind bootstrap output to exact deterministic InSpace floating-IP records."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pathlib
import re
import ssl
import tempfile
import urllib.error
import urllib.request
import uuid


MAX_RESPONSE_BYTES = 4 * 1024 * 1024
NAME_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,53}[a-z0-9])?$")


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        del req, fp, msg, headers, newurl
        raise RuntimeError(f"InSpace API returned redirect status {code}")


def canonical_uuid(value: object, label: str) -> str:
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise RuntimeError(f"{label} is not a canonical UUID")
    return value


def public_ipv4(value: object, label: str) -> str:
    address = ipaddress.ip_address(str(value))
    if (
        address.version != 4
        or not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_multicast
        or str(address) != value
    ):
        raise RuntimeError(f"{label} is not canonical public IPv4")
    return str(address)


def private_ipv4(value: object, label: str) -> str:
    address = ipaddress.ip_address(str(value))
    if (
        address.version != 4
        or not address.is_private
        or address.is_loopback
        or address.is_multicast
        or str(address) != value
    ):
        raise RuntimeError(f"{label} is not canonical private IPv4")
    return str(address)


def api_get(api_url: str, location: str, token: str, path: str) -> object:
    url = f"{api_url.rstrip('/')}/v1/{location}/{path}"
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "application/json",
            "User-Agent": "inspace-deploy-bootstrap-discovery/1",
            "apikey": token,
        },
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        RejectRedirects(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        with opener.open(request, timeout=30) as response:
            if response.status != 200:
                raise RuntimeError(f"InSpace API returned HTTP {response.status}")
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise RuntimeError("InSpace API response exceeded the size limit")
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"InSpace API returned HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"InSpace API request failed: {error.reason}") from error
    try:
        return json.loads(body, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("InSpace API returned malformed JSON") from error


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key}")
        result[key] = value
    return result


def atomic_write(path: pathlib.Path, value: dict[str, object]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = pathlib.Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cluster-config", required=True)
    parser.add_argument("--cluster", required=True)
    parser.add_argument("--replicas", required=True, type=int, choices=(1, 3))
    parser.add_argument("--billing-account-id", required=True, type=int)
    parser.add_argument("--location", required=True)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--ssh-username", required=True)
    parser.add_argument("--bootstrap-controller-version", required=True)
    parser.add_argument("--modules-version", required=True)
    args = parser.parse_args()

    token = os.environ.get("INSPACE_API_TOKEN", "")
    if not token:
        raise SystemExit("INSPACE_API_TOKEN is required")
    if not NAME_PATTERN.fullmatch(args.cluster):
        raise SystemExit("cluster is not a bounded lowercase DNS label")

    result = json.loads(pathlib.Path(args.result).read_text(encoding="utf-8"))
    if not isinstance(result, dict) or result.get("ready") is not True:
        raise SystemExit("bootstrap result is not ready")
    control_plane_ids = result.get("controlPlaneVMs")
    if (
        not isinstance(control_plane_ids, list)
        or len(control_plane_ids) != args.replicas
        or len(set(control_plane_ids)) != args.replicas
    ):
        raise SystemExit("bootstrap result has the wrong control-plane cardinality")
    control_plane_ids = [
        canonical_uuid(value, "bootstrap control-plane UUID")
        for value in control_plane_ids
    ]
    bastion_uuid = canonical_uuid(result.get("bastionVMUUID"), "bastion UUID")

    addresses = api_get(
        args.api_url, args.location, token, "network/ip_addresses"
    )
    if not isinstance(addresses, list):
        raise SystemExit("floating-IP inventory was not an array")

    expected_names = {f"{args.cluster}-bastion-ip"} | {
        f"{args.cluster}-cp{slot}-ip" for slot in range(args.replicas)
    }
    selected: dict[str, dict[str, object]] = {}
    for item in addresses:
        if not isinstance(item, dict) or item.get("is_deleted") is True:
            continue
        name = item.get("name")
        if name not in expected_names:
            continue
        if name in selected:
            raise SystemExit(f"duplicate active floating-IP name {name}")
        if item.get("billing_account_id") != args.billing_account_id:
            raise SystemExit(f"floating IP {name} belongs to another billing account")
        if (
            item.get("enabled") is not True
            or item.get("type") != "public"
            or item.get("assigned_to_resource_type") != "virtual_machine"
        ):
            raise SystemExit(f"floating IP {name} is not an assigned public VM address")
        selected[name] = item
    if set(selected) != expected_names:
        raise SystemExit("deterministic bootstrap floating-IP set is incomplete")

    bastion_fip = selected[f"{args.cluster}-bastion-ip"]
    if bastion_fip.get("assigned_to") != bastion_uuid:
        raise SystemExit("bastion floating IP is assigned to another VM")
    bastion_public = public_ipv4(bastion_fip.get("address"), "bastion address")
    bastion_private = private_ipv4(
        bastion_fip.get("assigned_to_private_ip"), "bastion private address"
    )
    if (
        result.get("bastionPublicIPv4") != bastion_public
        or result.get("bastionPrivateIPv4") != bastion_private
    ):
        raise SystemExit("bastion bootstrap output and floating-IP inventory disagree")

    control_planes: list[dict[str, object]] = []
    observed_ids: set[str] = set()
    for slot in range(args.replicas):
        name = f"{args.cluster}-cp{slot}"
        fip_name = f"{name}-ip"
        item = selected[fip_name]
        vm_uuid = canonical_uuid(item.get("assigned_to"), f"{name} UUID")
        observed_ids.add(vm_uuid)
        control_planes.append(
            {
                "name": name,
                "uuid": vm_uuid,
                "privateIPv4": private_ipv4(
                    item.get("assigned_to_private_ip"), f"{name} private address"
                ),
                "publicIPv4": public_ipv4(item.get("address"), f"{name} address"),
                "floatingIPName": fip_name,
            }
        )
    if observed_ids != set(control_plane_ids):
        raise SystemExit("control-plane result UUIDs and deterministic FIPs disagree")

    config_data = pathlib.Path(args.cluster_config).read_bytes()
    import hashlib

    state: dict[str, object] = {
        "schema": "inspace-deploy-state-v1",
        "clusterName": args.cluster,
        "controlPlaneReplicas": args.replicas,
        "bootstrapControllerVersion": args.bootstrap_controller_version,
        "modulesVersion": args.modules_version,
        "owner": result.get("owner"),
        "clusterConfigSHA256": hashlib.sha256(config_data).hexdigest(),
        "sshUsername": args.ssh_username,
        "bastionName": f"{args.cluster}-bastion",
        "bastionVMUUID": bastion_uuid,
        "bastionPublicIPv4": bastion_public,
        "bastionPrivateIPv4": bastion_private,
        "controlPlanes": control_planes,
        "controlPlaneEndpoint": result.get("controlPlaneEndpoint"),
        "privateControlPlaneEndpoint": result.get("privateControlPlaneEndpoint"),
        "privateRegistrationEndpoint": result.get("privateRegistrationEndpoint"),
        "firewallUUID": result.get("firewallUUID"),
        "bastionFirewallUUID": result.get("bastionFirewallUUID"),
        "bootstrapCacheAddress": result.get("bootstrapCacheAddress", ""),
        "bootstrapCacheEndpoint": result.get("bootstrapCacheEndpoint", ""),
        "bootstrapCacheRegistry": result.get("bootstrapCacheRegistry", ""),
        "bootstrapCacheCABundle": result.get("bootstrapCacheCABundle", ""),
    }
    atomic_write(pathlib.Path(args.output), state)


if __name__ == "__main__":
    main()
