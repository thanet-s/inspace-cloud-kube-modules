#!/usr/bin/env python3
"""Prove the CCM-managed Cilium Node IPAM load-balancer contract end to end."""

import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import socket
import ssl
import stat
import subprocess
import urllib.parse
import urllib.request


SERVICE_SPECS = {
    "inspace-e2e-node-traefik": {
        "ports": (
            {"name": "http", "protocol": "TCP", "port": 80, "targetPort": "traefik-http", "marker": "node-traefik-http"},
            {"name": "https", "protocol": "TCP", "port": 443, "targetPort": "traefik-https", "marker": "node-traefik-https"},
            {"name": "http3", "protocol": "UDP", "port": 443, "targetPort": "traefik-http3", "marker": "node-traefik-http3"},
        ),
        "mode": "public-node-shared",
        "mode_annotation": False,
    },
    "inspace-e2e-node-shared-b": {
        "ports": (
            {"name": "http", "protocol": "TCP", "port": 18081, "targetPort": "shared-b", "marker": "node-shared-b"},
        ),
        "mode": "public-node-shared",
        "mode_annotation": False,
    },
    "inspace-e2e-node-shared-conflict": {
        "ports": (
            {"name": "http", "protocol": "TCP", "port": 80, "targetPort": "conflict-target", "marker": "node-shared-conflict"},
        ),
        "mode": "public-node-shared",
        "mode_annotation": False,
    },
    "inspace-e2e-node-dedicated": {
        "ports": (
            {"name": "http", "protocol": "TCP", "port": 18082, "targetPort": "dedicated", "marker": "node-dedicated"},
        ),
        "mode": "public-node-dedicated",
        "mode_annotation": True,
    },
}
PARTIAL_DELETED_SERVICE = "inspace-e2e-node-shared-b"
RETAINED_SHARED_SERVICE = "inspace-e2e-node-traefik"
LEGACY_SERVICE_NAMES = {"inspace-e2e-node-shared-a"}

NODE_LOAD_BALANCER_CLASS = "inspace.cloud/node"
CILIUM_NODE_CLASS = "io.cilium/node"
SHARD_PATTERN = re.compile(r"^inlb-[0-9a-f]{8}$")
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
IMMUTABLE_INVENTORY_KEYS = {"vms", "firewalls", "floatingIPs", "loadBalancers", "disks"}


def fail(message: str) -> None:
    raise SystemExit(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def active(item: object) -> bool:
    return (
        isinstance(item, dict)
        and item.get("is_deleted") is not True
        and str(item.get("status", "")).lower() != "deleted"
    )


def api_get(path: str):
    base = os.environ["INSPACE_API_URL"].rstrip("/")
    location = os.environ["INSPACE_LOCATION"]
    request = urllib.request.Request(
        f"{base}/v1/{location}/{path}",
        headers={
            "apikey": os.environ["INSPACE_API_TOKEN"],
            "User-Agent": "inspace-rke2-e2e-node-load-balancer/1",
        },
    )
    with urllib.request.urlopen(
        request, timeout=60, context=ssl.create_default_context()
    ) as response:
        return json.load(response)


def kubectl(kubeconfig: str, *arguments: str):
    process = subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig, *arguments, "-o", "json"],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if process.returncode != 0:
        fail(process.stderr.strip() or f"kubectl {' '.join(arguments)} failed")
    try:
        return json.loads(process.stdout)
    except json.JSONDecodeError as error:
        fail(f"kubectl {' '.join(arguments)} did not return JSON: {error}")


def description(vm: object) -> dict:
    if not isinstance(vm, dict):
        return {}
    try:
        value = json.loads(vm.get("description", "{}"))
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def short_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def hash16(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def ownership_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:32]


def managed_name(cluster: str, suffix: str) -> str:
    base = f"{cluster}-{suffix}".lower().strip("-")
    if len(base) <= 63:
        return base
    return base[:54].rstrip("-") + "-" + short_hash(base)


def floating_ip_name(cluster: str, nodeclaim: str) -> str:
    base = "".join(
        character
        if character.isascii()
        and (character.islower() or character.isdigit() or character == "-")
        else "-"
        for character in nodeclaim.lower()
    ).strip("-")
    if not base.startswith("inspace-e2e-"):
        base = "karpenter-" + base
    base = base[:52].rstrip("-")
    suffix = hashlib.sha256(f"{cluster}\0{nodeclaim}".encode()).hexdigest()[:10]
    return f"{base}-{suffix}"


def firewall_name(cluster: str, service_uid: str, policy_hash: str) -> str:
    return f"inlb-{short_hash(cluster)}-{service_uid}-{policy_hash}"


def generic_nlb_name(cluster: str, service_uid: str) -> str:
    return f"k8s-{hash16(cluster)}-{hash16(service_uid)}"


def cluster_icmp_firewall_name(cluster: str) -> tuple[str, str]:
    policy_hash = short_hash("icmp|inbound|any")
    return f"inlb-{ownership_hash(cluster)}-icmp-{policy_hash}", policy_hash


def canonical_service_policy_keys(rules: list[dict]) -> tuple[str, ...]:
    require(bool(rules), "Service firewall policy must contain at least one rule")
    keys = []
    seen_ports = set()
    seen_rules = set()
    for index, rule in enumerate(rules):
        protocol = rule.get("protocol")
        direction = rule.get("direction")
        port_start = rule.get("port_start")
        port_end = rule.get("port_end")
        require(direction == "inbound", f"Service firewall rule {index} must be inbound")
        require(protocol in ("tcp", "udp"), f"Service firewall rule {index} protocol must be tcp or udp")
        require(
            isinstance(port_start, int)
            and not isinstance(port_start, bool)
            and port_start == port_end
            and 1 <= port_start <= 65535,
            f"Service firewall rule {index} must expose one explicit valid port",
        )
        port_key = (protocol, port_start)
        require(port_key not in seen_ports, f"Service firewall duplicates public {protocol}/{port_start}")
        seen_ports.add(port_key)
        endpoint_type = rule.get("endpoint_spec_type")
        raw_endpoints = rule.get("endpoint_spec")
        if endpoint_type == "any":
            require(raw_endpoints in (None, []), f"Service firewall rule {index} endpoint Any must have no prefixes")
            endpoints = []
        else:
            require(endpoint_type == "ip_prefixes", f"Service firewall rule {index} endpoint type is unsupported")
            require(isinstance(raw_endpoints, list) and raw_endpoints, f"Service firewall rule {index} lacks IPv4 prefixes")
            endpoints = []
            for value in raw_endpoints:
                try:
                    prefix = ipaddress.ip_network(value, strict=True)
                except (TypeError, ValueError) as error:
                    fail(f"Service firewall rule {index} has invalid prefix {value!r}: {error}")
                require(prefix.version == 4 and str(prefix) == value, f"Service firewall rule {index} prefix must be canonical IPv4 CIDR")
                endpoints.append(value)
            require(len(set(endpoints)) == len(endpoints), f"Service firewall rule {index} repeats an IPv4 prefix")
            endpoints.sort()
        key = f"{protocol}|{port_start}|{endpoint_type}|{','.join(endpoints)}"
        require(key not in seen_rules, f"Service firewall rule {index} duplicates a canonical rule")
        seen_rules.add(key)
        keys.append(key)
    return tuple(sorted(keys))


def canonical_service_policy_hash(rules: list[dict]) -> str:
    return short_hash("\n".join(canonical_service_policy_keys(rules)))


def expected_service_firewall_rules(service: dict) -> list[dict]:
    ranges = service.get("spec", {}).get("loadBalancerSourceRanges", [])
    require(isinstance(ranges, list), f"Service/{service['metadata']['name']} source ranges must be an array")
    canonical_ranges = []
    for value in ranges:
        try:
            prefix = ipaddress.ip_network(value, strict=True)
        except (TypeError, ValueError) as error:
            fail(f"Service/{service['metadata']['name']} has invalid source range {value!r}: {error}")
        require(prefix.version == 4 and str(prefix) == value, f"Service/{service['metadata']['name']} source range must be canonical IPv4 CIDR")
        canonical_ranges.append(value)
    require(len(set(canonical_ranges)) == len(canonical_ranges), f"Service/{service['metadata']['name']} repeats a source range")
    canonical_ranges.sort()
    rules = []
    for port in service.get("spec", {}).get("ports", []):
        rule = {
            "protocol": str(port.get("protocol", "TCP")).lower(),
            "direction": "inbound",
            "port_start": port.get("port"),
            "port_end": port.get("port"),
            "endpoint_spec_type": "ip_prefixes" if canonical_ranges else "any",
            "endpoint_spec": canonical_ranges or None,
        }
        rules.append(rule)
    return rules


def ping_public_ip(address: str) -> None:
    process = subprocess.run(
        ["ping", "-c", "1", "-W", "5", address],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    require(process.returncode == 0, f"Node-LB FIP {address} did not answer ICMP echo")


def probe_udp(address: str, port: int, expected: str) -> None:
    payload = b"inspace-e2e-node-lb\n"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(10)
        client.sendto(payload, (address, port))
        try:
            response, peer = client.recvfrom(4096)
        except TimeoutError:
            fail(f"UDP/{port} on Node-LB FIP {address} did not answer")
    require(peer[0] == address and peer[1] == port, f"UDP/{port} returned from unexpected peer {peer}")
    require(response.decode("utf-8").strip() == expected, f"UDP/{port} on Node-LB FIP {address} returned the wrong backend marker")


def require_nonvirtual(value: object, label: str) -> None:
    if value is not None and value is not False:
        fail(f"{label} must be a non-virtual InSpace address")


def ready(node: dict) -> bool:
    return any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in node.get("status", {}).get("conditions", [])
    )


def addresses(node: dict, address_type: str) -> list[str]:
    return [
        address.get("address")
        for address in node.get("status", {}).get("addresses", [])
        if address.get("type") == address_type and address.get("address")
    ]


def service_external_ip(service: dict) -> str:
    ingress = service.get("status", {}).get("loadBalancer", {}).get("ingress", [])
    require(len(ingress) == 1, f"Service/{service['metadata']['name']} must publish exactly one ExternalIP")
    require(
        isinstance(ingress[0], dict)
        and isinstance(ingress[0].get("ip"), str)
        and not ingress[0].get("hostname"),
        f"Service/{service['metadata']['name']} must publish an IP, not a hostname",
    )
    try:
        parsed = ipaddress.ip_address(ingress[0]["ip"])
    except ValueError as error:
        fail(f"Service/{service['metadata']['name']} returned an invalid ExternalIP: {error}")
    require(parsed.version == 4 and parsed.is_global, f"Service/{service['metadata']['name']} ExternalIP must be public IPv4")
    return str(parsed)


def requirement_map(nodepool: dict) -> dict[str, tuple[str, tuple[str, ...]]]:
    result = {}
    requirements = nodepool.get("spec", {}).get("template", {}).get("spec", {}).get("requirements", [])
    require(isinstance(requirements, list), "NodePool requirements must be an array")
    for requirement in requirements:
        key = requirement.get("key") if isinstance(requirement, dict) else None
        require(isinstance(key, str) and key not in result, "NodePool requirements must have unique string keys")
        values = requirement.get("values", [])
        require(isinstance(values, list) and all(isinstance(value, str) for value in values), f"NodePool requirement {key} values are invalid")
        result[key] = (requirement.get("operator"), tuple(values))
    return result


def assigned_firewalls(firewalls: list[dict], vm_uuid: str) -> set[str]:
    result = set()
    for firewall in firewalls:
        assignments = firewall.get("resources_assigned", [])
        require(isinstance(assignments, list), "cloud firewall assignments must be an array")
        matching = [
            item
            for item in assignments
            if isinstance(item, dict)
            and item.get("resource_type") == "vm"
            and item.get("resource_uuid") == vm_uuid
        ]
        require(len(matching) <= 1, f"firewall {firewall.get('uuid')} has duplicate VM assignments")
        if matching:
            result.add(firewall.get("uuid"))
    return result


def owned_node_load_balancer_nlbs(
    state: dict,
    services: list[dict],
    load_balancers: list[dict],
) -> list[str]:
    """Return only active NLBs attributable to this cluster's Node-LB path."""
    cluster = state.get("clusterName")
    require(isinstance(cluster, str) and cluster, "ownership journal lacks clusterName")
    cluster_nlb_prefix = f"k8s-{hash16(cluster)}-"
    generic_pattern = re.compile(rf"^{re.escape(cluster_nlb_prefix)}[0-9a-f]{{16}}$")

    journal_names = state.get("nodeLoadBalancerForbiddenLoadBalancerNames", [])
    require(
        isinstance(journal_names, list)
        and all(isinstance(name, str) and generic_pattern.fullmatch(name) for name in journal_names)
        and journal_names == sorted(set(journal_names)),
        "Node-LB NLB deny journal is invalid",
    )
    forbidden_names = set(journal_names)

    # The paid TCP acceptance Service is a legitimate generic CCM NLB. Allow
    # only its exact current or journaled deterministic identity; every other
    # cluster-prefixed generic NLB is an orphan or a Node-LB routing failure.
    allowed_generic_names = set()
    journal_public_name = state.get("serviceLoadBalancerName")
    if journal_public_name is not None:
        require(
            isinstance(journal_public_name, str)
            and generic_pattern.fullmatch(journal_public_name),
            "public Service NLB journal identity is invalid",
        )
        allowed_generic_names.add(journal_public_name)
    for service in services:
        if not isinstance(service, dict):
            continue
        metadata = service.get("metadata", {})
        if metadata.get("namespace", "default") != "default" or metadata.get("name") != "inspace-e2e-web":
            continue
        uid = metadata.get("uid")
        require(isinstance(uid, str) and uid, "live paid public Service lacks a UID")
        allowed_generic_names.add(generic_nlb_name(cluster, uid))

    service_policy_prefix = f"inlb-{short_hash(cluster)}-"
    icmp_policy_prefix = f"inlb-{ownership_hash(cluster)}-icmp-"
    owned = []
    for load_balancer in load_balancers:
        require(isinstance(load_balancer, dict), "load-balancer list contains a non-object")
        if not active(load_balancer):
            continue
        name = load_balancer.get("display_name") or load_balancer.get("name") or ""
        require(isinstance(name, str) and name, "active load balancer lacks a deterministic display name")
        is_owned = (
            name in forbidden_names
            or str(name).startswith(service_policy_prefix)
            or str(name).startswith(icmp_policy_prefix)
            or (generic_pattern.fullmatch(str(name)) is not None and name not in allowed_generic_names)
        )
        if is_owned:
            identity = load_balancer.get("uuid") or name
            require(isinstance(identity, str) and identity, "owned Node-LB NLB lacks a stable identity")
            owned.append(identity)
    return sorted(owned)


def get_vm_detail(vm_uuid: str) -> dict:
    detail = api_get("user-resource/vm?" + urllib.parse.urlencode({"uuid": vm_uuid}))
    require(isinstance(detail, dict) and detail.get("uuid") == vm_uuid, f"VM/{vm_uuid} detail readback is not authoritative")
    return detail


def immutable_load_balancer_baseline(path: pathlib.Path) -> list[str]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail("immutable account baseline inventory is absent")
    require(
        stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600,
        "immutable account baseline inventory must be a mode-0600 regular file",
    )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"immutable account baseline inventory is unreadable: {error}")
    require(
        isinstance(value, dict) and set(value) == IMMUTABLE_INVENTORY_KEYS,
        "immutable account baseline inventory has an unexpected schema",
    )
    identities = value.get("loadBalancers")
    require(
        isinstance(identities, list)
        and all(isinstance(identity, str) and identity for identity in identities)
        and identities == sorted(set(identities)),
        "immutable account NLB baseline is invalid",
    )
    return identities


def active_load_balancer_uuids(load_balancers: list[dict]) -> list[str]:
    identities = []
    for load_balancer in load_balancers:
        require(isinstance(load_balancer, dict), "load-balancer list contains a non-object")
        if not active(load_balancer):
            continue
        identity = load_balancer.get("uuid")
        require(isinstance(identity, str) and identity, "active load balancer lacks a stable UUID")
        identities.append(identity)
    require(len(identities) == len(set(identities)), "active load-balancer inventory contains duplicate UUIDs")
    return sorted(identities)


def prove_absent(state: dict, kubeconfig: str, immutable_baseline_path: pathlib.Path) -> dict:
    cluster = state["clusterName"]
    immutable_nlb_uuids = immutable_load_balancer_baseline(immutable_baseline_path)
    all_services = kubectl(kubeconfig, "-n", "default", "get", "services").get("items", [])
    service_names = set(SERVICE_SPECS) | LEGACY_SERVICE_NAMES
    forbidden_services = service_names | {f"{name}-node-lb" for name in service_names}
    remaining_services = sorted(
        service.get("metadata", {}).get("name")
        for service in all_services
        if service.get("metadata", {}).get("name") in forbidden_services
    )
    require(not remaining_services, f"Node-LB Services still exist: {remaining_services}")

    load_balancers = api_get("network/load_balancers")
    require(isinstance(load_balancers, list), "load-balancer list did not return an array")
    # Validate the durable deny journal even when the immutable UUID set is
    # already equal; baseline resources themselves are never name-attributed.
    owned_node_load_balancer_nlbs(state, all_services, [])
    current_nlb_uuids = active_load_balancer_uuids(load_balancers)
    if current_nlb_uuids != immutable_nlb_uuids:
        owned_nlbs = owned_node_load_balancer_nlbs(state, all_services, load_balancers)
        require(
            not owned_nlbs,
            f"owned or stale Node-LB InSpace NLBs still exist and must not enter a new baseline: {owned_nlbs}",
        )
        fail(
            "active InSpace NLB UUIDs differ from the immutable pre-mutation account baseline: "
            f"current={current_nlb_uuids} baseline={immutable_nlb_uuids}"
        )

    selector = (
        "inspace.cloud.node-restriction.kubernetes.io/node-lb=true,"
        f"inspace.cloud.node-restriction.kubernetes.io/cluster={cluster}"
    )
    nodepools = kubectl(
        kubeconfig,
        "get",
        "nodepools",
        "-l",
        f"inspace.cloud/node-lb-managed=true,inspace.cloud/node-lb-cluster={cluster}",
    ).get("items", [])
    nodeclaims = [
        nodeclaim
        for nodeclaim in kubectl(kubeconfig, "get", "nodeclaims").get("items", [])
        if str(nodeclaim.get("metadata", {}).get("name", "")).startswith("inlb-")
    ]
    nodes = kubectl(kubeconfig, "get", "nodes", "-l", selector).get("items", [])
    require(not nodepools, "managed Node-LB NodePools still exist")
    require(not nodeclaims, "managed Node-LB NodeClaims still exist")
    require(not nodes, "managed Node-LB Nodes still exist")

    listed_vms = api_get("user-resource/vm/list")
    require(isinstance(listed_vms, list), "VM list did not return an array")
    node_lb_vms = []
    for vm in listed_vms:
        if not active(vm):
            continue
        record = description(vm)
        if (
            str(vm.get("name", "")).startswith(f"{cluster}-karp-inlb-")
            or (record.get("cluster") == cluster and record.get("firewallProfile") == "public-node-load-balancer")
        ):
            node_lb_vms.append(vm.get("uuid"))
    require(not node_lb_vms, f"managed Node-LB VMs still exist: {node_lb_vms}")

    firewalls = api_get("network/firewalls")
    require(isinstance(firewalls, list), "firewall list did not return an array")
    service_prefix = f"inlb-{short_hash(cluster)}-"
    icmp_prefix = f"inlb-{ownership_hash(cluster)}-icmp-"
    node_lb_firewalls = [
        firewall.get("uuid")
        for firewall in firewalls
        if active(firewall)
        and (
            str(firewall.get("display_name") or firewall.get("name") or "").startswith(service_prefix)
            or str(firewall.get("display_name") or firewall.get("name") or "").startswith(icmp_prefix)
        )
    ]
    require(not node_lb_firewalls, f"managed Node-LB firewalls still exist: {node_lb_firewalls}")

    floating_ips = api_get("network/ip_addresses")
    require(isinstance(floating_ips, list), "floating-IP list did not return an array")
    node_lb_fips = [
        address.get("name")
        for address in floating_ips
        if active(address) and str(address.get("name", "")).startswith("karpenter-inlb-")
    ]
    require(not node_lb_fips, f"managed Node-LB floating IPs still exist: {node_lb_fips}")
    return {
        "phase": "absent", "services": 0, "nodePools": 0, "vms": 0,
        "floatingIPs": 0, "firewalls": 0, "loadBalancers": 0,
    }


def prove_present(
    state: dict,
    kubeconfig: str,
    baseline_path: pathlib.Path,
    service_names: tuple[str, ...],
) -> dict:
    cluster = state["clusterName"]
    billing_account = int(os.environ["INSPACE_BILLING_ACCOUNT_ID"])
    amd_pool_uuid = os.environ["INSPACE_AMD_HOST_POOL_UUID"]
    location = os.environ["INSPACE_LOCATION"]
    base_firewall_uuid = state["firewallUUID"]

    services = {}
    service_results = {}
    services_by_shard: dict[str, list[str]] = {}
    omitted_services = set(SERVICE_SPECS) - set(service_names)
    all_default_services = kubectl(kubeconfig, "-n", "default", "get", "services").get("items", [])
    unexpected_omitted = sorted(
        item.get("metadata", {}).get("name")
        for item in all_default_services
        if item.get("metadata", {}).get("name") in omitted_services
        or item.get("metadata", {}).get("name") in {f"{name}-node-lb" for name in omitted_services}
    )
    require(not unexpected_omitted, f"deleted Node-LB Service owners still exist: {unexpected_omitted}")

    for name in service_names:
        contract = SERVICE_SPECS[name]
        service = kubectl(kubeconfig, "-n", "default", "get", "service", name)
        services[name] = service
        metadata = service.get("metadata", {})
        annotations = metadata.get("annotations", {})
        spec = service.get("spec", {})
        require(spec.get("type") == "LoadBalancer", f"Service/{name} must remain LoadBalancer")
        require(spec.get("loadBalancerClass") == NODE_LOAD_BALANCER_CLASS, f"Service/{name} must select {NODE_LOAD_BALANCER_CLASS}")
        require(spec.get("allocateLoadBalancerNodePorts") is False, f"Service/{name} must disable NodePorts")
        require(spec.get("externalTrafficPolicy") == "Cluster", f"Service/{name} must use Cluster traffic policy")
        ports = spec.get("ports", [])
        expected_ports = {
            (port["name"], port["protocol"], port["port"], port["targetPort"])
            for port in contract["ports"]
        }
        actual_ports = {
            (port.get("name"), port.get("protocol"), port.get("port"), port.get("targetPort"))
            for port in ports
            if port.get("nodePort", 0) == 0
        }
        require(
            len(ports) == len(expected_ports) and actual_ports == expected_ports,
            f"Service/{name} ports differ from the exact mixed TCP/UDP contract or include a NodePort",
        )
        require("service.inspace.cloud/node-lb-cpu" not in annotations, f"Service/{name} must exercise default CPU")
        require("service.inspace.cloud/node-lb-memory" not in annotations, f"Service/{name} must exercise default memory")
        if contract["mode_annotation"]:
            require(
                annotations.get("service.inspace.cloud/node-lb-mode") == contract["mode"],
                f"Service/{name} must select dedicated mode explicitly",
            )
        else:
            require(
                "service.inspace.cloud/node-lb-mode" not in annotations,
                f"Service/{name} must exercise the omitted-mode shared default",
            )
        require("service.inspace.cloud/node-lb" in metadata.get("finalizers", []), f"Service/{name} lacks the Node-LB cleanup finalizer")
        shard = annotations.get("service.inspace.cloud/node-lb-shard", "")
        require(SHARD_PATTERN.fullmatch(shard) is not None, f"Service/{name} lacks a managed shard identity")
        firewall_uuid = annotations.get("service.inspace.cloud/node-lb-firewall-uuid", "")
        firewall_hash = annotations.get("service.inspace.cloud/node-lb-firewall-hash", "")
        require(UUID_PATTERN.fullmatch(firewall_uuid) is not None, f"Service/{name} lacks a valid firewall UUID")
        require(re.fullmatch(r"[0-9a-f]{8}", firewall_hash or "") is not None, f"Service/{name} lacks a valid firewall policy hash")
        external_ip = service_external_ip(service)
        services_by_shard.setdefault(shard, []).append(name)
        service_results[name] = {
            "ip": external_ip,
            "ports": [dict(port) for port in contract["ports"]],
            "shard": shard,
            "firewallUUID": firewall_uuid,
            "firewallHash": firewall_hash,
            "uid": metadata.get("uid"),
        }

        shadow_name = f"{name}-node-lb"
        shadow = kubectl(kubeconfig, "-n", "default", "get", "service", shadow_name)
        shadow_metadata = shadow.get("metadata", {})
        shadow_spec = shadow.get("spec", {})
        require(shadow_spec.get("loadBalancerClass") == CILIUM_NODE_CLASS, f"Service/{shadow_name} must select Cilium Node IPAM")
        require(shadow_spec.get("allocateLoadBalancerNodePorts") is False, f"Service/{shadow_name} must disable NodePorts")
        require(shadow_spec.get("externalTrafficPolicy") == "Cluster", f"Service/{shadow_name} must use Cluster traffic policy")
        require(all(port.get("nodePort", 0) == 0 for port in shadow_spec.get("ports", [])), f"Service/{shadow_name} unexpectedly allocated a NodePort")
        require(shadow_metadata.get("labels", {}).get("inspace.cloud/node-lb-shadow") == "true", f"Service/{shadow_name} lacks the shadow label")
        require(
            shadow_metadata.get("labels", {}).get("inspace.cloud/node-lb-service-uid") == metadata.get("uid"),
            f"Service/{shadow_name} lacks the exact owner UID label",
        )
        owner_references = shadow_metadata.get("ownerReferences", [])
        require(
            len(owner_references) == 1
            and owner_references[0].get("apiVersion") == "v1"
            and owner_references[0].get("kind") == "Service"
            and owner_references[0].get("name") == name
            and owner_references[0].get("uid") == metadata.get("uid")
            and owner_references[0].get("controller") is True
            and owner_references[0].get("blockOwnerDeletion") is True,
            f"Service/{shadow_name} lacks exact controller ownership",
        )
        selector = (
            "inspace.cloud.node-restriction.kubernetes.io/node-lb=true,"
            f"inspace.cloud.node-restriction.kubernetes.io/cluster={cluster},"
            f"inspace.cloud.node-restriction.kubernetes.io/shard={shard},"
            "inspace.cloud.node-restriction.kubernetes.io/ready=true"
        )
        require(
            shadow_metadata.get("annotations", {}).get("io.cilium.nodeipam/match-node-labels") == selector,
            f"Service/{shadow_name} does not select only the ready managed shard",
        )
        require(
            shadow.get("status", {}).get("loadBalancer", {})
            == service.get("status", {}).get("loadBalancer", {}),
            f"Service/{name} status is not the exact owned shadow status",
        )

    traefik = service_results["inspace-e2e-node-traefik"]
    conflict = service_results["inspace-e2e-node-shared-conflict"]
    dedicated = service_results["inspace-e2e-node-dedicated"]
    if "inspace-e2e-node-shared-b" in service_results:
        shared_b = service_results["inspace-e2e-node-shared-b"]
        require(traefik["shard"] == shared_b["shard"] and traefik["ip"] == shared_b["ip"], "non-conflicting shared Services must reuse one shard and FIP")
    require(conflict["shard"] != traefik["shard"] and conflict["ip"] != traefik["ip"], "a conflicting shared TCP/80 port must allocate a new shard and FIP")
    require(dedicated["shard"] not in {traefik["shard"], conflict["shard"]}, "dedicated mode must own a distinct shard")
    require(len(services_by_shard) == 3, "the live Services must converge to exactly three Node-LB shards")

    nodeclass_name = managed_name(cluster, "node-lb")
    nodeclass = kubectl(kubeconfig, "get", "inspacenodeclass", nodeclass_name)
    nodeclass_labels = nodeclass.get("metadata", {}).get("labels", {})
    nodeclass_annotations = nodeclass.get("metadata", {}).get("annotations", {})
    nodeclass_spec = nodeclass.get("spec", {})
    require(nodeclass_labels.get("inspace.cloud/node-lb-managed") == "true" and nodeclass_labels.get("inspace.cloud/node-lb-cluster") == cluster, "generated NodeClass lacks exact managed ownership")
    require(
        nodeclass_spec.get("firewallProfile") == "public-node-load-balancer"
        and nodeclass_spec.get("rootDiskGiB") == 30
        and nodeclass_spec.get("reservePublicIPv4") is True,
        "generated NodeClass must use the public 30-GiB reserved-FIP profile",
    )
    require(
        all(field not in nodeclass_spec for field in ("sshUsername", "sshPublicKey", "additionalUserData")),
        "generated NodeClass must strip operator access and additional user data",
    )
    icmp_firewall_uuid = nodeclass_annotations.get("service.inspace.cloud/node-lb-icmp-firewall-uuid", "")
    require(UUID_PATTERN.fullmatch(icmp_firewall_uuid) is not None, "generated NodeClass lacks the durable cluster ICMP firewall identity")

    nodes_by_shard = {}
    nodeclaims_by_shard = {}
    for shard, service_names in services_by_shard.items():
        mode = SERVICE_SPECS[service_names[0]]["mode"]
        nodepool = kubectl(kubeconfig, "get", "nodepool", shard)
        labels = nodepool.get("metadata", {}).get("labels", {})
        template = nodepool.get("spec", {}).get("template", {})
        template_labels = template.get("metadata", {}).get("labels", {})
        template_spec = template.get("spec", {})
        require(
            labels.get("inspace.cloud/node-lb-managed") == "true"
            and labels.get("inspace.cloud/node-lb-cluster") == cluster
            and labels.get("inspace.cloud/node-lb-shard") == shard,
            f"NodePool/{shard} lacks exact managed ownership",
        )
        require(nodepool.get("spec", {}).get("replicas") == 1, f"NodePool/{shard} must default to one replica")
        require(nodepool.get("spec", {}).get("limits", {}).get("nodes") == "2", f"NodePool/{shard} must allow exactly one drift surge")
        require(
            template_labels.get("inspace.cloud.node-restriction.kubernetes.io/node-lb") == "true"
            and template_labels.get("inspace.cloud.node-restriction.kubernetes.io/cluster") == cluster
            and template_labels.get("inspace.cloud.node-restriction.kubernetes.io/shard") == shard
            and template_labels.get("inspace.cloud/node-lb-mode") == mode,
            f"NodePool/{shard} template labels do not match its shard profile",
        )
        taints = template_spec.get("taints", [])
        require(
            any(
                taint.get("key") == "inspace.cloud/node-lb"
                and taint.get("value") == "true"
                and taint.get("effect") == "NoSchedule"
                for taint in taints
            ),
            f"NodePool/{shard} must taint dedicated public capacity",
        )
        node_class_ref = template_spec.get("nodeClassRef", {})
        require(
            node_class_ref == {
                "group": "karpenter.inspace.cloud",
                "kind": "InSpaceNodeClass",
                "name": nodeclass_name,
            },
            f"NodePool/{shard} does not use the generated NodeClass",
        )
        requirements = requirement_map(nodepool)
        require(
            requirements
            == {
                "inspace.cloud/instance-cpu": ("In", ("1",)),
                "inspace.cloud/instance-memory": ("In", ("2048",)),
                "inspace.cloud/host-class": ("In", ("amd-epyc",)),
                "karpenter.sh/capacity-type": ("In", ("on-demand",)),
                "kubernetes.io/arch": ("In", ("amd64",)),
                "kubernetes.io/os": ("In", ("linux",)),
            },
            f"NodePool/{shard} must select exactly AMD 1-vCPU/2-GiB on-demand Linux amd64",
        )

        nodeclaims = kubectl(kubeconfig, "get", "nodeclaims", "-l", f"karpenter.sh/nodepool={shard}").get("items", [])
        nodes = kubectl(
            kubeconfig,
            "get",
            "nodes",
            "-l",
            "inspace.cloud.node-restriction.kubernetes.io/node-lb=true,"
            f"inspace.cloud.node-restriction.kubernetes.io/cluster={cluster},"
            f"inspace.cloud.node-restriction.kubernetes.io/shard={shard}",
        ).get("items", [])
        require(len(nodeclaims) == 1 and len(nodes) == 1, f"NodePool/{shard} must own exactly one NodeClaim and one Node")
        nodeclaim = nodeclaims[0]
        node = nodes[0]
        nodeclaims_by_shard[shard] = nodeclaim
        nodes_by_shard[shard] = node
        nodeclaim_metadata = nodeclaim.get("metadata", {})
        nodeclaim_labels = nodeclaim_metadata.get("labels", {})
        nodeclaim_ref = nodeclaim.get("spec", {}).get("nodeClassRef", {})
        nodeclaim_status = nodeclaim.get("status", {})
        node_metadata = node.get("metadata", {})
        nodeclaim_pool_owners = [
            owner
            for owner in nodeclaim_metadata.get("ownerReferences", [])
            if owner.get("apiVersion") == "karpenter.sh/v1" and owner.get("kind") == "NodePool"
        ]
        node_claim_owners = [
            owner
            for owner in node_metadata.get("ownerReferences", [])
            if owner.get("apiVersion") == "karpenter.sh/v1" and owner.get("kind") == "NodeClaim"
        ]
        require(
            nodeclaim_labels.get("karpenter.sh/nodepool") == shard
            and nodeclaim_labels.get("inspace.cloud.node-restriction.kubernetes.io/node-lb") == "true"
            and nodeclaim_labels.get("inspace.cloud.node-restriction.kubernetes.io/cluster") == cluster
            and nodeclaim_labels.get("inspace.cloud.node-restriction.kubernetes.io/shard") == shard
            and nodeclaim_ref == node_class_ref,
            f"NodeClaim/{nodeclaim_metadata.get('name')} lacks the protected managed NodeClass chain",
        )
        require(
            len(nodeclaim_pool_owners) == 1
            and nodeclaim_pool_owners[0].get("name") == shard
            and nodeclaim_pool_owners[0].get("uid") == nodepool.get("metadata", {}).get("uid")
            and nodeclaim_pool_owners[0].get("blockOwnerDeletion") is True,
            f"NodeClaim/{nodeclaim_metadata.get('name')} lacks the exact NodePool owner identity",
        )
        require(
            nodeclaim_status.get("providerID") == node.get("spec", {}).get("providerID")
            and nodeclaim_status.get("nodeName") == node_metadata.get("name")
            and len(node_claim_owners) == 1
            and node_claim_owners[0].get("name") == nodeclaim_metadata.get("name")
            and node_claim_owners[0].get("uid") == nodeclaim_metadata.get("uid")
            and node_claim_owners[0].get("blockOwnerDeletion") is True,
            f"Node/{node_metadata.get('name')} lacks the exact unique NodeClaim identity",
        )
        node_labels = node.get("metadata", {}).get("labels", {})
        require(ready(node), f"Node/{node['metadata']['name']} is not Ready")
        require(
            node_labels.get("inspace.cloud.node-restriction.kubernetes.io/ready") == "true"
            and node_labels.get("inspace.cloud/host-class") == "amd-epyc"
            and node_labels.get("inspace.cloud/instance-cpu") == "1"
            and node_labels.get("inspace.cloud/instance-memory") == "2048",
            f"Node/{node['metadata']['name']} lacks the exact ready AMD shape labels",
        )
        require(
            any(
                taint.get("key") == "inspace.cloud/node-lb"
                and taint.get("value") == "true"
                and taint.get("effect") == "NoSchedule"
                for taint in node.get("spec", {}).get("taints", [])
            ),
            f"Node/{node['metadata']['name']} lost the dedicated Node-LB taint",
        )
        expected_external_ip = service_results[service_names[0]]["ip"]
        require(addresses(node, "ExternalIP") == [expected_external_ip], f"Node/{node['metadata']['name']} ExternalIP differs from its Services")
        require(
            all(service_results[name]["ip"] == expected_external_ip for name in service_names),
            f"all Services on shard {shard} must publish its exact Node ExternalIP",
        )

    app_pods = kubectl(kubeconfig, "-n", "default", "get", "pods", "-l", "app=inspace-e2e-node-lb").get("items", [])
    require(len(app_pods) == 1, "Node-LB data-path workload must have exactly one Pod")
    app_node = app_pods[0].get("spec", {}).get("nodeName", "")
    require(app_node and all(app_node != node["metadata"]["name"] for node in nodes_by_shard.values()), "application workload must not run on tainted Node-LB capacity")

    listed_vms = api_get("user-resource/vm/list")
    firewalls = [firewall for firewall in api_get("network/firewalls") if active(firewall)]
    floating_ips = [address for address in api_get("network/ip_addresses") if active(address)]
    require(isinstance(listed_vms, list), "VM list did not return an array")
    require(isinstance(firewalls, list), "firewall list did not return an array")
    require(isinstance(floating_ips, list), "floating-IP list did not return an array")
    firewall_by_uuid = {firewall.get("uuid"): firewall for firewall in firewalls}
    require(len(firewall_by_uuid) == len(firewalls), "active firewall list contains duplicate UUIDs")
    network = api_get(f"network/network/{os.environ['INSPACE_NETWORK_UUID']}")
    require(isinstance(network, dict) and network.get("uuid") == os.environ["INSPACE_NETWORK_UUID"], "configured VPC lookup was not authoritative")
    subnet = ipaddress.ip_network(network["subnet"], strict=False)

    expected_vm_uuids = set()
    expected_fip_names = set()
    expected_service_firewalls = set()
    vm_by_shard = {}
    for shard, node in nodes_by_shard.items():
        provider_id = node.get("spec", {}).get("providerID", "")
        prefix = f"inspace://{location}/"
        require(provider_id.startswith(prefix), f"Node/{node['metadata']['name']} has an invalid providerID")
        vm_uuid = provider_id.removeprefix(prefix)
        require(UUID_PATTERN.fullmatch(vm_uuid) is not None, f"Node/{node['metadata']['name']} providerID lacks a VM UUID")
        nodeclaim_name = nodeclaims_by_shard[shard]["metadata"]["name"]
        expected_name = f"{cluster}-karp-{nodeclaim_name}"
        require(node["metadata"]["name"] == expected_name, f"Node/{node['metadata']['name']} does not use the cluster-karp-NodeClaim identity")
        matching_summaries = [vm for vm in listed_vms if active(vm) and vm.get("uuid") == vm_uuid and vm.get("name") == expected_name]
        require(len(matching_summaries) == 1, f"Node/{expected_name} lacks one exact active VM list identity")
        vm = get_vm_detail(vm_uuid)
        record = description(vm)
        expected_fip_name = floating_ip_name(cluster, nodeclaim_name)
        require(
            record.get("schema") == "karpenter.inspace.cloud/v3"
            and record.get("cluster") == cluster
            and record.get("nodeClaim") == nodeclaim_name
            and record.get("vmName") == expected_name
            and record.get("hostClass") == "amd-epyc"
            and record.get("hostPoolUUID") == amd_pool_uuid
            and record.get("vCPU") == 1
            and record.get("memoryGiB") == 2
            and record.get("rootDiskGiB") == 30
            and record.get("firewallUUID") == base_firewall_uuid
            and record.get("firewallProfile") == "public-node-load-balancer"
            and record.get("networkUUID") == os.environ["INSPACE_NETWORK_UUID"]
            and record.get("billingAccountID") == billing_account
            and record.get("floatingIPName") == expected_fip_name
            and record.get("publicIPv4") in (None, "")
            and vm.get("designated_pool_uuid") == amd_pool_uuid,
            f"VM/{expected_name} lacks the exact AMD 1-vCPU/2-GiB/30-GiB public ownership contract",
        )
        storage = vm.get("storage", [])
        root_disks = [disk for disk in storage if isinstance(disk, dict) and disk.get("primary") is True]
        require(len(root_disks) == 1 and root_disks[0].get("size") == 30, f"VM/{expected_name} must have exactly one 30-GiB primary disk")
        internal_ips = addresses(node, "InternalIP")
        require(len(internal_ips) == 1 and ipaddress.ip_address(internal_ips[0]) in subnet, f"Node/{expected_name} must have one VPC InternalIP")
        require(vm.get("private_ipv4") == internal_ips[0], f"VM/{expected_name} private IPv4 differs from the Node InternalIP")
        require(list(network.get("vm_uuids", [])).count(vm_uuid) == 1, f"VM/{expected_name} is not an exact VPC member")
        if vm.get("hostname"):
            require(vm.get("hostname") == expected_name, f"VM/{expected_name} returned a conflicting hostname")
        matches = [address for address in floating_ips if address.get("name") == expected_fip_name]
        require(len(matches) == 1, f"VM/{expected_name} must own one deterministic floating IP")
        floating_ip = matches[0]
        require_nonvirtual(floating_ip.get("is_virtual"), f"VM/{expected_name} floating IP")
        require(
            floating_ip.get("billing_account_id") == billing_account
            and floating_ip.get("assigned_to") == vm_uuid
            and floating_ip.get("assigned_to_resource_type") == "virtual_machine"
            and floating_ip.get("enabled") is True
            and floating_ip.get("type") == "public"
            and floating_ip.get("address") == service_results[services_by_shard[shard][0]]["ip"],
            f"VM/{expected_name} floating IP does not match its exact Node and Service ExternalIP",
        )
        require(vm.get("public_ipv4") in (None, ""), f"VM/{expected_name} must not copy the reserved FIP into public_ipv4")
        expected_vm_uuids.add(vm_uuid)
        expected_fip_names.add(expected_fip_name)
        vm_by_shard[shard] = vm_uuid
        for service_name in services_by_shard[shard]:
            service_results[service_name]["vmUUID"] = vm_uuid

    require(len(expected_vm_uuids) == 3 and len(expected_fip_names) == 3, "three shards must own exactly three VMs and three FIPs")
    active_node_lb_vm_uuids = {
        vm.get("uuid")
        for vm in listed_vms
        if active(vm) and str(vm.get("name", "")).startswith(f"{cluster}-karp-inlb-")
    }
    require(active_node_lb_vm_uuids == expected_vm_uuids, "active Node-LB VM inventory differs from the three live shards")
    active_node_lb_fip_names = {
        address.get("name")
        for address in floating_ips
        if str(address.get("name", "")).startswith("karpenter-inlb-")
    }
    require(active_node_lb_fip_names == expected_fip_names, "active Node-LB FIP inventory differs from the three live shards")

    icmp_name, icmp_hash = cluster_icmp_firewall_name(cluster)
    icmp_firewall = firewall_by_uuid.get(icmp_firewall_uuid)
    require(icmp_firewall is not None, "cluster ICMP firewall is absent")
    require(
        (icmp_firewall.get("display_name") or icmp_firewall.get("name")) == icmp_name
        and icmp_hash == short_hash("icmp|inbound|any")
        and icmp_firewall.get("billing_account_id") == billing_account
        and icmp_firewall.get("description", "")
        in ("", "Managed InSpace node load balancer cluster ICMP firewall"),
        "cluster ICMP firewall lacks the deterministic cluster ownership contract",
    )
    icmp_rules = icmp_firewall.get("rules", [])
    require(
        len(icmp_rules) == 1
        and icmp_rules[0].get("protocol") == "icmp"
        and icmp_rules[0].get("direction") == "inbound"
        and icmp_rules[0].get("port_start") is None
        and icmp_rules[0].get("port_end") is None
        and icmp_rules[0].get("endpoint_spec_type") == "any"
        and icmp_rules[0].get("endpoint_spec") in (None, []),
        "cluster ICMP firewall must contain only portless inbound ICMP from Any",
    )
    icmp_assignments = icmp_firewall.get("resources_assigned", [])
    require(
        len(icmp_assignments) == len(expected_vm_uuids)
        and {
            assignment.get("resource_uuid")
            for assignment in icmp_assignments
            if assignment.get("resource_type") == "vm"
        }
        == expected_vm_uuids,
        "cluster ICMP firewall must target every and only authoritative Node-LB VM",
    )

    expected_firewalls_by_vm = {
        vm_uuid: {base_firewall_uuid, icmp_firewall_uuid}
        for vm_uuid in expected_vm_uuids
    }
    for name, result in service_results.items():
        firewall_uuid = result["firewallUUID"]
        expected_service_firewalls.add(firewall_uuid)
        firewall = firewall_by_uuid.get(firewall_uuid)
        require(firewall is not None, f"Service/{name} firewall is absent")
        expected_name = firewall_name(cluster, result["uid"], result["firewallHash"])
        actual_name = firewall.get("display_name") or firewall.get("name")
        require(actual_name == expected_name, f"Service/{name} firewall name is not deterministic")
        require(
            firewall.get("billing_account_id") == billing_account
            and firewall.get("description", "") in ("", "Managed InSpace node load balancer Service firewall"),
            f"Service/{name} firewall ownership is invalid",
        )
        rules = firewall.get("rules", [])
        expected_rules = expected_service_firewall_rules(services[name])
        actual_policy_keys = canonical_service_policy_keys(rules)
        expected_policy_keys = canonical_service_policy_keys(expected_rules)
        actual_policy_hash = canonical_service_policy_hash(rules)
        require(
            len(rules) == len(expected_rules)
            and actual_policy_keys == expected_policy_keys
            and actual_policy_hash == result["firewallHash"]
            and actual_policy_hash == canonical_service_policy_hash(expected_rules),
            f"Service/{name} firewall must contain exactly its canonical TCP/UDP-only policy",
        )
        assignments = firewall.get("resources_assigned", [])
        expected_vm_uuid = vm_by_shard[result["shard"]]
        require(
            len(assignments) == 1
            and assignments[0].get("resource_type") == "vm"
            and assignments[0].get("resource_uuid") == expected_vm_uuid,
            f"Service/{name} firewall must target exactly its one shard VM",
        )
        expected_firewalls_by_vm[expected_vm_uuid].add(firewall_uuid)

    firewall_prefix = f"inlb-{short_hash(cluster)}-"
    icmp_firewall_prefix = f"inlb-{ownership_hash(cluster)}-icmp-"
    active_node_lb_firewalls = {
        firewall.get("uuid")
        for firewall in firewalls
        if str(firewall.get("display_name") or firewall.get("name") or "").startswith(firewall_prefix)
        or str(firewall.get("display_name") or firewall.get("name") or "").startswith(icmp_firewall_prefix)
    }
    require(
        active_node_lb_firewalls == expected_service_firewalls | {icmp_firewall_uuid},
        "active Node-LB firewall inventory differs from the live Service policies plus one cluster ICMP policy",
    )
    for vm_uuid, expected in expected_firewalls_by_vm.items():
        require(assigned_firewalls(firewalls, vm_uuid) == expected, f"VM/{vm_uuid} has unexpected cloud firewall assignments")

    unique_public_ips = sorted({result["ip"] for result in service_results.values()})
    require(len(unique_public_ips) == 3, "three live Node-LB shards must publish three unique FIPs")
    for address in unique_public_ips:
        ping_public_ip(address)

    http_probes = []
    udp_probes = []
    marker_prefix = cluster
    for service_name, result in service_results.items():
        for port in result["ports"]:
            probe = {
                "service": service_name,
                "ip": result["ip"],
                "port": port["port"],
                "markerSuffix": port["marker"],
            }
            if port["protocol"] == "UDP":
                probe_udp(result["ip"], port["port"], f"{marker_prefix}-{port['marker']}")
                udp_probes.append(probe)
            else:
                http_probes.append(probe)

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    require(isinstance(baseline, dict) and isinstance(baseline.get("loadBalancers"), list), "Node-LB baseline inventory is invalid")
    active_load_balancers = [load_balancer for load_balancer in api_get("network/load_balancers") if active(load_balancer)]
    require(
        sorted(load_balancer.get("uuid") for load_balancer in active_load_balancers)
        == baseline["loadBalancers"],
        "Cilium Node IPAM acceptance must not create an InSpace NLB",
    )

    return {
        "phase": "present",
        "nodeClass": nodeclass_name,
        "icmpFirewallUUID": icmp_firewall_uuid,
        "shards": sorted(services_by_shard),
        "vms": sorted(expected_vm_uuids),
        "floatingIPs": sorted(expected_fip_names),
        "firewalls": sorted(expected_service_firewalls | {icmp_firewall_uuid}),
        "services": service_results,
        "httpProbes": http_probes,
        "udpProbes": udp_probes,
    }


def prove_partial(
    state: dict,
    kubeconfig: str,
    baseline_path: pathlib.Path,
    deleted_firewall_uuid: str,
    retained_shard: str,
    retained_vm: str,
    retained_ip: str,
    retained_icmp_firewall_uuid: str,
    retained_service_firewall_uuid: str,
) -> dict:
    service_names = tuple(name for name in SERVICE_SPECS if name != PARTIAL_DELETED_SERVICE)
    result = prove_present(state, kubeconfig, baseline_path, service_names)
    require(UUID_PATTERN.fullmatch(deleted_firewall_uuid) is not None, "partial proof lacks the deleted Service firewall UUID")
    require(deleted_firewall_uuid not in result["firewalls"], "deleted shared-member Service firewall is still active")
    retained = result["services"][RETAINED_SHARED_SERVICE]
    require(
        retained["shard"] == retained_shard
        and retained["vmUUID"] == retained_vm
        and retained["ip"] == retained_ip
        and result["icmpFirewallUUID"] == retained_icmp_firewall_uuid,
        "partial shared-member deletion replaced the sibling shard, VM, FIP, or cluster ICMP firewall",
    )
    require(
        retained["firewallUUID"] == retained_service_firewall_uuid,
        "partial shared-member deletion replaced the retained sibling Service firewall",
    )
    result["phase"] = "partial"
    result["deletedService"] = PARTIAL_DELETED_SERVICE
    result["deletedFirewallUUID"] = deleted_firewall_uuid
    result["retainedServiceFirewallUUID"] = retained["firewallUUID"]
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--expect", choices=("present", "partial", "absent"), required=True)
    parser.add_argument("--baseline")
    parser.add_argument("--immutable-baseline")
    parser.add_argument("--deleted-firewall")
    parser.add_argument("--retained-shard")
    parser.add_argument("--retained-vm")
    parser.add_argument("--retained-ip")
    parser.add_argument("--retained-icmp-firewall")
    parser.add_argument("--retained-service-firewall")
    args = parser.parse_args()
    state = json.loads(pathlib.Path(args.state).read_text(encoding="utf-8"))
    require(isinstance(state, dict) and isinstance(state.get("clusterName"), str), "ownership journal lacks clusterName")
    if args.expect == "absent":
        require(bool(args.immutable_baseline), "--immutable-baseline is required for the absent proof")
        result = prove_absent(state, args.kubeconfig, pathlib.Path(args.immutable_baseline))
    elif args.expect == "present":
        require(bool(args.baseline), "--baseline is required for the present proof")
        result = prove_present(state, args.kubeconfig, pathlib.Path(args.baseline), tuple(SERVICE_SPECS))
    else:
        required = {
            "--baseline": args.baseline,
            "--deleted-firewall": args.deleted_firewall,
            "--retained-shard": args.retained_shard,
            "--retained-vm": args.retained_vm,
            "--retained-ip": args.retained_ip,
            "--retained-icmp-firewall": args.retained_icmp_firewall,
            "--retained-service-firewall": args.retained_service_firewall,
        }
        require(all(required.values()), "partial proof requires " + ", ".join(required))
        result = prove_partial(
            state,
            args.kubeconfig,
            pathlib.Path(args.baseline),
            args.deleted_firewall,
            args.retained_shard,
            args.retained_vm,
            args.retained_ip,
            args.retained_icmp_firewall,
            args.retained_service_firewall,
        )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
