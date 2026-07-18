#!/usr/bin/env python3
"""Prove the user-owned public-node-local capacity and exposure contract."""

import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import socket
import stat
import subprocess
import urllib.parse
import urllib.request

from cloud_identity_journal import record_known_cloud_identities
from strict_inspace_api import location_api_get


SERVICE_NAME = "inspace-e2e-public-local"
DEPLOYMENT_NAME = SERVICE_NAME
MODE_ANNOTATION = "service.inspace.cloud/node-lb-mode"
POOL_ANNOTATION = "service.inspace.cloud/node-lb-pool"
POOL_LABEL = "inspace.cloud.node-restriction.kubernetes.io/public-local-pool"
LOCAL_FINALIZER = "service.inspace.cloud/public-node-local"
FIREWALL_UUID_ANNOTATION = "service.inspace.cloud/node-lb-firewall-uuid"
FIREWALL_HASH_ANNOTATION = "service.inspace.cloud/node-lb-firewall-hash"
DATAPATH_CLASS = "inspace.cloud/node-datapath"
DATAPATH_LABEL = "inspace.cloud/node-lb-datapath"
SERVICE_ID_LABEL = "inspace.cloud/node-lb-service-id"
DATAPATH_POOL_ANNOTATION = "service.inspace.cloud/public-node-local-pool"
IMMUTABLE_INVENTORY_KEYS = {
    "vms", "networks", "firewalls", "floatingIPs", "loadBalancers", "disks",
    "buckets", "servicePackages",
}
VM_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


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
    return location_api_get(
        path,
        user_agent="inspace-rke2-e2e-public-node-local/2",
    )


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
    if not process.stdout.strip():
        return None
    try:
        return json.loads(process.stdout)
    except json.JSONDecodeError as error:
        fail(f"kubectl {' '.join(arguments)} did not return JSON: {error}")


def read_state(path: pathlib.Path) -> dict:
    metadata = path.lstat()
    require(
        stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600,
        "ownership journal must be a mode-0600 regular file",
    )
    state = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(state, dict), "ownership journal must contain an object")
    return state


def read_baseline(path: pathlib.Path) -> dict:
    metadata = path.lstat()
    require(
        stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600,
        "account baseline must be a mode-0600 regular file",
    )
    baseline = json.loads(path.read_text(encoding="utf-8"))
    require(
        isinstance(baseline, dict) and set(baseline) == IMMUTABLE_INVENTORY_KEYS,
        "account baseline has an unexpected schema",
    )
    return baseline


def require_nlb_baseline(baseline: dict) -> None:
    current = api_get("network/load_balancers")
    require(isinstance(current, list), "load-balancer API did not return an array")
    current_ids = [item.get("uuid") for item in current if active(item)]
    require(
        all(isinstance(value, str) and value for value in current_ids),
        "active load balancer lacks a stable UUID",
    )
    current_ids.sort()
    require(
        current_ids == baseline["loadBalancers"],
        "public-node-local acceptance created or removed an InSpace NLB",
    )


def effective_name(firewall: dict) -> str:
    return str(firewall.get("display_name") or firewall.get("name") or "")


def description(vm: dict) -> dict:
    try:
        value = json.loads(vm.get("description", "{}"))
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def deterministic_floating_ip_name(cluster: str, nodeclaim: str) -> str:
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


def service_firewall_identity(cluster: str, service_uid: str) -> tuple[str, str]:
    canonical = "tcp|80|any|\nudp|443|any|"
    policy_hash = hashlib.sha256(canonical.encode()).hexdigest()[:8]
    cluster_hash = hashlib.sha256(cluster.encode()).hexdigest()[:8]
    return f"inlb-{cluster_hash}-{service_uid}-{policy_hash}", policy_hash


def service_identity(namespace: str, name: str, uid: str) -> str:
    canonical = f"{namespace}\0{name}\0{uid}"
    return hashlib.sha256(canonical.encode()).hexdigest()[:52]


def datapath_name(namespace: str, name: str, uid: str) -> str:
    return f"inlb-dp-{service_identity(namespace, name, uid)}"


def node_ready(node: dict) -> bool:
    return any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in node.get("status", {}).get("conditions", [])
    )


def one_node_address(node: dict, address_type: str) -> str:
    values = [
        address.get("address")
        for address in node.get("status", {}).get("addresses", [])
        if address.get("type") == address_type
    ]
    require(len(values) == 1 and isinstance(values[0], str), f"Node must have one {address_type}")
    return values[0]


def nodepool_requirements(nodepool: dict) -> dict[str, tuple[str, tuple[str, ...]]]:
    result = {}
    for requirement in nodepool.get("spec", {}).get("template", {}).get("spec", {}).get("requirements", []):
        key = requirement.get("key")
        require(isinstance(key, str) and key and key not in result, "NodePool has invalid duplicate requirements")
        values = requirement.get("values", [])
        require(isinstance(values, list) and all(isinstance(value, str) for value in values), "NodePool requirement values are invalid")
        result[key] = (requirement.get("operator"), tuple(values))
    return result


def require_single_owner_reference(
    child: dict,
    api_version: str,
    kind: str,
    name: str,
    uid: str,
    description: str,
) -> None:
    matches = [
        reference
        for reference in child.get("metadata", {}).get("ownerReferences", [])
        if reference.get("apiVersion") == api_version and reference.get("kind") == kind
    ]
    require(
        len(matches) == 1
        and matches[0].get("name") == name
        and matches[0].get("uid") == uid
        and matches[0].get("blockOwnerDeletion") is True,
        f"{description} lacks its exact {kind} owner identity",
    )


def require_nodeclass_reference(value: object, nodeclass_name: str, description: str) -> None:
    require(
        value
        == {
            "group": "karpenter.inspace.cloud",
            "kind": "InSpaceNodeClass",
            "name": nodeclass_name,
        },
        f"{description} references the wrong InSpaceNodeClass",
    )


def require_capacity_objects(
    state: dict,
    kubeconfig: str,
    expect_ready_pods: bool,
) -> tuple[list[dict], list[dict]]:
    pool_name = state["publicLocalNodePoolName"]
    pool_value = state["publicLocalPool"]
    nodeclass_name = state["publicLocalNodeClassName"]
    nodepool = kubectl(kubeconfig, "get", "nodepool", pool_name)
    require(nodepool is not None, f"NodePool/{pool_name} is absent")
    template = nodepool.get("spec", {}).get("template", {})
    require(nodepool.get("spec", {}).get("replicas") == 1, "edge NodePool must maintain one static replica")
    require(
        nodepool.get("spec", {}).get("limits", {}).get("nodes") in (2, "2"),
        "edge NodePool must allow exactly one replacement surge",
    )
    require(
        template.get("metadata", {}).get("labels", {}).get(POOL_LABEL) == pool_value,
        "edge NodePool lacks the protected public-local pool label",
    )
    template_spec = template.get("spec", {})
    require(template_spec.get("expireAfter") == "Never", "edge NodePool must disable expiration")
    require_nodeclass_reference(
        template_spec.get("nodeClassRef"), nodeclass_name, "edge NodePool"
    )
    require(
        template_spec.get("taints") == [{
            "key": "inspace.cloud/public-local",
            "value": "true",
            "effect": "NoSchedule",
        }],
        "edge NodePool must have the exact public-local NoSchedule taint",
    )
    requirements = nodepool_requirements(nodepool)
    expected_requirements = {
        "inspace.cloud/instance-family": ("In", ("general",)),
        "inspace.cloud/instance-cpu": ("In", ("1",)),
        "inspace.cloud/instance-memory": ("In", ("2048",)),
        "inspace.cloud/host-class": ("In", ("amd-epyc",)),
        "karpenter.sh/capacity-type": ("In", ("on-demand",)),
        "kubernetes.io/arch": ("In", ("amd64",)),
        "kubernetes.io/os": ("In", ("linux",)),
    }
    require(requirements == expected_requirements, "edge NodePool requirements drifted from the exact 1-core/2-GiB AMD profile")

    nodeclass = kubectl(kubeconfig, "get", "inspacenodeclass", nodeclass_name)
    require(nodeclass is not None, f"InSpaceNodeClass/{nodeclass_name} is absent")
    nodeclass_spec = nodeclass.get("spec", {})
    nodeclass_status = nodeclass.get("status", {})
    require(
        nodeclass_spec.get("clusterName") == state["clusterName"]
        and nodeclass_spec.get("billingAccountID")
        == int(os.environ["INSPACE_BILLING_ACCOUNT_ID"])
        and nodeclass_spec.get("location") == os.environ["INSPACE_LOCATION"]
        and nodeclass_spec.get("networkUUID") == os.environ["INSPACE_NETWORK_UUID"]
        and nodeclass_spec.get("privateLoadBalancerPool")
        == {
            "start": os.environ["INSPACE_PRIVATE_LOAD_BALANCER_POOL_START"],
            "stop": os.environ["INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP"],
        }
        and nodeclass_spec.get("firewallProfile") == "public-node-local"
        and nodeclass_spec.get("firewallUUID") == state["firewallUUID"]
        and nodeclass_spec.get("reservePublicIPv4") is True
        and nodeclass_spec.get("rootDiskGiB") == 30,
        "edge NodeClass lacks the exact cluster/billing/network/firewall/FIP/30-GiB contract",
    )
    require(
        nodeclass_status.get("firewallUUID") == state["firewallUUID"]
        and sorted(nodeclass_status.get("hostPoolUUIDs", []))
        == sorted(
            [
                os.environ["INSPACE_AMD_HOST_POOL_UUID"],
                "aac7dd66-f390-4edd-80c0-dd7cae49bd99",
            ]
        ),
        "edge NodeClass status does not confirm its exact firewall and supported host pools",
    )

    claims = kubectl(kubeconfig, "get", "nodeclaims", "-l", f"karpenter.sh/nodepool={pool_name}")
    nodes = kubectl(kubeconfig, "get", "nodes", "-l", f"karpenter.sh/nodepool={pool_name}")
    require(claims is not None and len(claims.get("items", [])) == 1, "edge NodePool must own exactly one NodeClaim")
    require(nodes is not None and len(nodes.get("items", [])) == 1, "edge NodePool must own exactly one Node")
    claim = claims["items"][0]
    node = nodes["items"][0]
    node_name = node.get("metadata", {}).get("name", "")
    node_uid = node.get("metadata", {}).get("uid", "")
    claim_name = claim.get("metadata", {}).get("name", "")
    claim_uid = claim.get("metadata", {}).get("uid", "")
    nodepool_uid = nodepool.get("metadata", {}).get("uid", "")
    require(
        all(
            isinstance(value, str) and value
            for value in (node_name, node_uid, claim_name, claim_uid, nodepool_uid)
        ),
        "edge Node/NodeClaim/NodePool lacks a stable name or UID",
    )
    labels = node.get("metadata", {}).get("labels", {})
    require(node_ready(node), "edge Node is not Ready")
    require(node.get("metadata", {}).get("deletionTimestamp") is None, "edge Node is deleting")
    require(
        labels.get(POOL_LABEL) == pool_value
        and labels.get("inspace.cloud/host-class") == "amd-epyc"
        and labels.get("inspace.cloud/instance-cpu") == "1"
        and labels.get("inspace.cloud/instance-memory") == "2048",
        "edge Node lacks the protected pool or exact resolved capacity labels",
    )
    require(
        "node-role.kubernetes.io/control-plane" not in labels
        and "node-role.kubernetes.io/master" not in labels
        and labels.get("node.kubernetes.io/exclude-from-external-load-balancers") != "true",
        "edge Node is control-plane or excluded from external load balancers",
    )
    require(
        any(
            taint.get("key") == "inspace.cloud/public-local"
            and taint.get("value") == "true"
            and taint.get("effect") == "NoSchedule"
            for taint in node.get("spec", {}).get("taints", [])
        ),
        "edge Node lacks the public-local taint",
    )
    require(
        claim.get("metadata", {}).get("labels", {}).get(POOL_LABEL) == pool_value,
        "edge NodeClaim lacks the protected pool identity",
    )
    require(
        labels.get("karpenter.sh/nodepool") == pool_name
        and claim.get("metadata", {}).get("labels", {}).get("karpenter.sh/nodepool")
        == pool_name,
        "edge Node and NodeClaim do not bind to the exact NodePool name",
    )
    claim_status = claim.get("status", {})
    require(
        claim_status.get("providerID") == node.get("spec", {}).get("providerID")
        and claim_status.get("nodeName") == node_name,
        "edge NodeClaim status does not bind the exact Node providerID and name",
    )
    require_single_owner_reference(
        node,
        "karpenter.sh/v1",
        "NodeClaim",
        claim_name,
        claim_uid,
        "edge Node",
    )
    require_single_owner_reference(
        claim,
        "karpenter.sh/v1",
        "NodePool",
        pool_name,
        nodepool_uid,
        "edge NodeClaim",
    )
    require_nodeclass_reference(
        claim.get("spec", {}).get("nodeClassRef"), nodeclass_name, "edge NodeClaim"
    )

    deployment = kubectl(kubeconfig, "-n", "default", "get", "deployment", DEPLOYMENT_NAME)
    require(deployment is not None, f"Deployment/{DEPLOYMENT_NAME} is absent")
    require(
        deployment.get("spec", {}).get("template", {}).get("spec", {}).get("nodeSelector", {}).get(POOL_LABEL) == pool_value,
        "edge workload does not select the protected pool label",
    )
    pods = kubectl(kubeconfig, "-n", "default", "get", "pods", "-l", f"app={SERVICE_NAME}")
    pod_items = [] if pods is None else pods.get("items", [])
    if expect_ready_pods:
        require(len(pod_items) == 1, "edge workload must have exactly one Pod")
        pod = pod_items[0]
        require(
            pod.get("spec", {}).get("nodeName") == node.get("metadata", {}).get("name")
            and pod.get("status", {}).get("phase") == "Running"
            and any(
                condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in pod.get("status", {}).get("conditions", [])
            ),
            "edge workload Pod is not Ready on the selected edge Node",
        )
    else:
        require(len(pod_items) == 0, "withdrawn edge workload still has a Pod")
    return [node], [claim]


def cloud_capacity(state: dict, nodes: list[dict], claims: list[dict], require_service_firewall: bool) -> tuple[list[dict], list[dict], list[dict]]:
    cluster = state["clusterName"]
    pool_name = state["publicLocalNodePoolName"]
    billing_account = int(os.environ["INSPACE_BILLING_ACCOUNT_ID"])
    network_uuid = os.environ["INSPACE_NETWORK_UUID"]
    amd_pool_uuid = os.environ["INSPACE_AMD_HOST_POOL_UUID"]
    vm_summaries = api_get("user-resource/vm/list")
    addresses = api_get("network/ip_addresses")
    firewalls = api_get("network/firewalls")
    require(all(isinstance(value, list) for value in (vm_summaries, addresses, firewalls)), "cloud list API returned a non-array")
    network = api_get(f"network/network/{network_uuid}")
    require(
        isinstance(network, dict) and network.get("uuid") == network_uuid,
        "configured VPC lookup was not authoritative",
    )
    subnet = ipaddress.ip_network(network["subnet"], strict=False)
    active_addresses = [item for item in addresses if active(item)]
    active_firewalls = [item for item in firewalls if active(item)]
    proof_nodes = []
    vm_uuids = []
    for node, claim in zip(nodes, claims):
        node_name = node["metadata"]["name"]
        claim_name = claim["metadata"]["name"]
        provider_id = node.get("spec", {}).get("providerID", "")
        prefix = f"inspace://{os.environ['INSPACE_LOCATION']}/"
        require(provider_id.startswith(prefix), "edge Node providerID has the wrong location")
        vm_uuid = provider_id.removeprefix(prefix)
        require(VM_UUID_PATTERN.fullmatch(vm_uuid) is not None, "edge Node providerID lacks a VM UUID")
        summaries = [item for item in vm_summaries if active(item) and item.get("uuid") == vm_uuid and item.get("name") == node_name]
        require(len(summaries) == 1, "edge Node does not resolve to one exact active VM")
        query = urllib.parse.urlencode({"uuid": vm_uuid})
        vm = api_get(f"user-resource/vm?{query}")
        require(isinstance(vm, dict) and vm.get("uuid") == vm_uuid and vm.get("name") == node_name, "edge VM detail contradicts its list identity")
        record = description(vm)
        fip_name = deterministic_floating_ip_name(cluster, claim_name)
        require(
            record.get("schema") == "karpenter.inspace.cloud/v3"
            and record.get("cluster") == cluster
            and record.get("nodePool") == pool_name
            and record.get("nodeClaim") == claim_name
            and record.get("vmName") == node_name
            and record.get("hostClass") == "amd-epyc"
            and record.get("hostPoolUUID") == amd_pool_uuid
            and record.get("instanceType") == "is-general-1c-2g"
            and record.get("vCPU") == 1
            and record.get("memoryGiB") == 2
            and record.get("rootDiskGiB") == 30
            and record.get("firewallProfile") == "public-node-local"
            and record.get("firewallUUID") == state["firewallUUID"]
            and record.get("networkUUID") == network_uuid
            and record.get("billingAccountID") == billing_account
            and record.get("floatingIPName") == fip_name
            and record.get("publicIPv4") in (None, "")
            and vm.get("vcpu") == 1
            and vm.get("memory") == 2048
            and vm.get("designated_pool_uuid") == amd_pool_uuid
            and vm.get("public_ipv4") in (None, ""),
            "edge VM lacks exact Karpenter ownership, network, billing, FIP, AMD pool, or 1-core/2-GiB shape",
        )
        root_disks = [disk for disk in vm.get("storage", []) if isinstance(disk, dict) and disk.get("primary") is True]
        require(len(root_disks) == 1 and root_disks[0].get("size") == 30, "edge VM must have one 30-GiB root disk")
        private_ip = one_node_address(node, "InternalIP")
        require(
            vm.get("private_ipv4") == private_ip
            and ipaddress.ip_address(private_ip) in subnet
            and list(network.get("vm_uuids", [])).count(vm_uuid) == 1,
            "edge VM private address or exact configured-VPC membership differs from its Node",
        )
        fips = [item for item in active_addresses if item.get("name") == fip_name]
        require(len(fips) == 1, "edge Node lacks its deterministic Karpenter FIP")
        fip = fips[0]
        public_ip = ipaddress.ip_address(str(fip.get("address")))
        require(
            public_ip.version == 4
            and public_ip.is_global
            and fip.get("billing_account_id") == billing_account
            and fip.get("assigned_to") == vm_uuid
            and fip.get("assigned_to_resource_type") == "virtual_machine"
            and fip.get("enabled") is True
            and fip.get("type") == "public"
            and fip.get("is_virtual") in (None, False)
            and fip.get("assigned_to_private_ip") == private_ip,
            "edge Karpenter FIP lacks the exact active VM/private-address assignment",
        )
        assigned_addresses = [
            item for item in active_addresses if item.get("assigned_to") == vm_uuid
        ]
        require(
            len(assigned_addresses) == 1 and assigned_addresses[0] == fip,
            "edge VM has an additional or foreign-named active FIP",
        )
        require(one_node_address(node, "ExternalIP") == str(public_ip), "edge Node ExternalIP differs from its Karpenter FIP")
        assigned_firewalls = sorted(
            firewall.get("uuid")
            for firewall in active_firewalls
            if any(
                resource.get("resource_type", "").lower() == "vm"
                and resource.get("resource_uuid") == vm_uuid
                for resource in firewall.get("resources_assigned", [])
            )
        )
        expected_count = 2 if require_service_firewall else 1
        require(
            len(assigned_firewalls) == expected_count
            and state["firewallUUID"] in assigned_firewalls,
            "edge VM has an unexpected firewall assignment set",
        )
        proof_nodes.append({
            "node": node_name,
            "nodeClaim": claim_name,
            "vmUUID": vm_uuid,
            "privateIP": private_ip,
            "publicIP": str(public_ip),
            "fipName": fip_name,
            "assignedFirewallUUIDs": assigned_firewalls,
        })
        vm_uuids.append(vm_uuid)
    return proof_nodes, active_firewalls, vm_uuids


def ready_endpoint_nodes(kubeconfig: str) -> list[str]:
    slices = kubectl(
        kubeconfig,
        "-n",
        "default",
        "get",
        "endpointslices",
        "-l",
        f"kubernetes.io/service-name={SERVICE_NAME}",
    )
    result = []
    for endpoint_slice in ([] if slices is None else slices.get("items", [])):
        endpoints = endpoint_slice.get("endpoints")
        if endpoints is None:
            continue
        require(isinstance(endpoints, list), "EndpointSlice endpoints must be an array or null")
        for endpoint in endpoints:
            conditions = endpoint.get("conditions", {})
            if conditions.get("ready") is True and conditions.get("terminating") is not True:
                node_name = endpoint.get("nodeName")
                require(isinstance(node_name, str) and node_name, "Ready local endpoint lacks nodeName")
                result.append(node_name)
    require(len(result) == len(set(result)), "Service has multiple Ready endpoints on one edge Node")
    return sorted(result)


def service_firewall(service: dict, firewalls: list[dict], cluster: str, vm_uuids: list[str], assigned: bool) -> dict:
    uid = service.get("metadata", {}).get("uid", "")
    name, policy_hash = service_firewall_identity(cluster, uid)
    matches = [firewall for firewall in firewalls if effective_name(firewall) == name]
    require(len(matches) == 1, "expected exactly one deterministic public-local Service firewall")
    firewall = matches[0]
    rules = firewall.get("rules", [])
    require(
        len(rules) == 2 and all(isinstance(rule, dict) for rule in rules),
        "public-local Service firewall must contain exactly two rules",
    )
    canonical_rules = sorted(
        (
            rule.get("protocol"),
            rule.get("direction"),
            rule.get("port_start"),
            rule.get("port_end"),
            rule.get("endpoint_spec_type"),
            tuple(rule.get("endpoint_spec") or []),
        )
        for rule in rules
    )
    require(
        firewall.get("description") in (None, "", "Managed InSpace node load balancer Service firewall")
        and firewall.get("billing_account_id") == int(os.environ["INSPACE_BILLING_ACCOUNT_ID"])
        and canonical_rules
        == [
            ("tcp", "inbound", 80, 80, "any", ()),
            ("udp", "inbound", 443, 443, "any", ()),
        ],
        "public-local Service firewall policy or ownership is not exact",
    )
    assignments = sorted(
        (resource.get("resource_type"), resource.get("resource_uuid"))
        for resource in firewall.get("resources_assigned", [])
    )
    expected_assignments = sorted(("vm", vm_uuid) for vm_uuid in vm_uuids) if assigned else []
    require(
        assignments == expected_assignments,
        "public-local Service firewall targets the wrong or a non-VM resource set",
    )
    annotations = service.get("metadata", {}).get("annotations", {})
    require(
        annotations.get(FIREWALL_UUID_ANNOTATION) == firewall.get("uuid")
        and annotations.get(FIREWALL_HASH_ANNOTATION) == policy_hash,
        "Service lacks the exact applied firewall UUID/hash ledger",
    )
    pending = [
        key for key, value in annotations.items()
        if key.startswith("service.inspace.cloud/node-lb-")
        and ("pending" in key or "assigning" in key)
        and value not in (None, "")
    ]
    require(not pending, f"Service retains unresolved firewall mutation state: {pending}")
    return {"uuid": firewall.get("uuid"), "name": name, "hash": policy_hash}


def require_service_contract(service: dict, state: dict) -> None:
    metadata = service.get("metadata", {})
    spec = service.get("spec", {})
    require(
        metadata.get("annotations", {}).get(MODE_ANNOTATION) == "public-node-local"
        and metadata.get("annotations", {}).get(POOL_ANNOTATION) == state["publicLocalPool"],
        "Service lacks the exact public-node-local mode and pool annotations",
    )
    ports = spec.get("ports", [])
    require(
        len(ports) == 2 and all(isinstance(port, dict) for port in ports),
        "Service must expose exactly two ports",
    )
    ports_by_name = {port.get("name"): port for port in ports}
    http = ports_by_name.get("http", {})
    http3 = ports_by_name.get("http3", {})
    health_check_node_port = spec.get("healthCheckNodePort")
    require(
        spec.get("type") == "LoadBalancer"
        and spec.get("loadBalancerClass") == "inspace.cloud/node"
        and spec.get("allocateLoadBalancerNodePorts") is False
        and spec.get("externalTrafficPolicy") == "Local"
        and spec.get("publishNotReadyAddresses") in (None, False)
        and spec.get("selector") == {"app": SERVICE_NAME}
        and set(ports_by_name) == {"http", "http3"}
        and http.get("protocol") == "TCP"
        and http.get("port") == 80
        and http.get("targetPort") == "http"
        and http.get("nodePort") in (None, 0)
        and http3.get("protocol") == "UDP"
        and http3.get("port") == 443
        and http3.get("targetPort") == "http3"
        and http3.get("nodePort") in (None, 0)
        and isinstance(health_check_node_port, int)
        and 30000 <= health_check_node_port <= 32767
        and not spec.get("externalIPs")
        and not spec.get("loadBalancerIP"),
        "Service drifted from the TCP/UDP Local contract with no data-port NodePort and one allocated health-check port",
    )
    require(LOCAL_FINALIZER in metadata.get("finalizers", []), "Service lacks the public-node-local cleanup finalizer")


def require_datapath_contract(
    kubeconfig: str,
    service: dict,
    state: dict,
    expected_private_ips: list[str],
) -> dict:
    metadata = service.get("metadata", {})
    namespace = metadata.get("namespace", "default")
    uid = metadata.get("uid", "")
    require(isinstance(uid, str) and uid, "parent Service lacks a UID")
    identity = service_identity(namespace, SERVICE_NAME, uid)
    name = f"inlb-dp-{identity}"
    child = kubectl(kubeconfig, "-n", namespace, "get", "service", name)
    require(child is not None, f"private datapath Service/{name} is absent")
    child_metadata = child.get("metadata", {})
    labels = child_metadata.get("labels", {})
    annotations = child_metadata.get("annotations", {})
    owners = child_metadata.get("ownerReferences", [])
    require(
        labels.get(DATAPATH_LABEL) == "true"
        and labels.get(SERVICE_ID_LABEL) == identity
        and annotations.get(DATAPATH_POOL_ANNOTATION) == state["publicLocalPool"],
        "private datapath lacks its exact public-local identity",
    )
    require(
        owners == [{
            "apiVersion": "v1",
            "kind": "Service",
            "name": SERVICE_NAME,
            "uid": uid,
            "controller": True,
            "blockOwnerDeletion": True,
        }],
        "private datapath lacks the exact parent Service owner reference",
    )
    spec = child.get("spec", {})
    ports = spec.get("ports", [])
    require(
        len(ports) == 2 and all(isinstance(port, dict) for port in ports),
        "private datapath must expose exactly two ports",
    )
    ports_by_name = {port.get("name"): port for port in ports}
    http = ports_by_name.get("http", {})
    http3 = ports_by_name.get("http3", {})
    health_check_node_port = spec.get("healthCheckNodePort")
    parent_health_check_node_port = service.get("spec", {}).get("healthCheckNodePort")
    require(
        spec.get("type") == "LoadBalancer"
        and spec.get("loadBalancerClass") == DATAPATH_CLASS
        and spec.get("allocateLoadBalancerNodePorts") is False
        and spec.get("externalTrafficPolicy") == "Local"
        and spec.get("publishNotReadyAddresses") in (None, False)
        and spec.get("selector") == {"app": SERVICE_NAME}
        and set(ports_by_name) == {"http", "http3"}
        and http.get("protocol") == "TCP"
        and http.get("port") == 80
        and http.get("targetPort") == "http"
        and http.get("nodePort") in (None, 0)
        and http3.get("protocol") == "UDP"
        and http3.get("port") == 443
        and http3.get("targetPort") == "http3"
        and http3.get("nodePort") in (None, 0)
        and isinstance(health_check_node_port, int)
        and 30000 <= health_check_node_port <= 32767
        and health_check_node_port != parent_health_check_node_port
        and not spec.get("externalIPs")
        and not spec.get("loadBalancerIP"),
        "private datapath drifted from the TCP/UDP Local child contract with no data-port NodePort and one allocated health-check port",
    )
    ingress = child.get("status", {}).get("loadBalancer", {}).get("ingress", [])
    require(
        ingress == [{"ip": address, "ipMode": "VIP"} for address in expected_private_ips],
        "private datapath VIP status does not exactly equal eligible Node InternalIPs",
    )
    return {"name": name, "identity": identity, "statusIPs": expected_private_ips}


def require_datapath_absent(kubeconfig: str, namespace: str, name: str, uid: str) -> None:
    child_name = datapath_name(namespace, name, uid)
    child = kubectl(
        kubeconfig,
        "-n",
        namespace,
        "get",
        "service",
        child_name,
        "--ignore-not-found=true",
    )
    require(child is None, f"private datapath Service/{child_name} remains")


def parse_remote_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        address = ipaddress.ip_address(text)
    except ValueError as error:
        fail(f"public-local backend returned malformed client source {value!r}: {error}")
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def http_probe(proof: dict, marker: str) -> str:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    sources = []
    public_ips = {item["publicIP"] for item in proof["nodes"]}
    for address in sorted(public_ips):
        with opener.open(f"http://{address}/", timeout=10) as response:
            body = response.read().decode().strip()
        require(body == marker, f"public-local FIP {address} returned the wrong backend marker")
        with opener.open(f"http://{address}/cgi-bin/source", timeout=10) as response:
            source_text = response.read().decode().strip()
        source = parse_remote_address(source_text)
        require(
            source.version == 4 and source.is_global and str(source) not in public_ips,
            "public-local backend did not retain a global client source distinct from the edge FIP",
        )
        sources.append(str(source))
    require(len(set(sources)) == 1, "public-local probes observed inconsistent client source addresses")
    return sources[0]


def udp_probe(proof: dict, marker: str) -> list[str]:
    payload = b"inspace-e2e-public-local\n"
    probed = []
    for address in sorted({item["publicIP"] for item in proof["nodes"]}):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(10)
            client.sendto(payload, (address, 443))
            try:
                response, peer = client.recvfrom(4096)
            except TimeoutError:
                fail(f"UDP/443 on public-local FIP {address} did not answer")
        require(
            peer[0] == address and peer[1] == 443,
            f"UDP/443 returned from unexpected peer {peer}",
        )
        require(
            response.decode("utf-8").strip() == marker,
            f"UDP/443 on public-local FIP {address} returned the wrong backend marker",
        )
        probed.append(address)
    return probed


def require_replacement(anchor: dict, current: dict) -> None:
    old_nodes = anchor.get("nodes", [])
    new_nodes = current.get("nodes", [])
    require(
        len(old_nodes) == 1 and len(new_nodes) == 1,
        "replacement proof requires exactly one old and one new edge node",
    )
    old = old_nodes[0]
    new = new_nodes[0]
    for key in ("node", "nodeClaim", "vmUUID", "fipName"):
        require(
            isinstance(old.get(key), str)
            and old.get(key)
            and isinstance(new.get(key), str)
            and new.get(key)
            and old[key] != new[key],
            f"edge replacement retained old {key}",
        )
    require(
        current.get("firewall") == anchor.get("firewall"),
        "edge replacement changed the Service-owned firewall identity",
    )

    active_vms = [item for item in api_get("user-resource/vm/list") if active(item)]
    require(
        not any(item.get("uuid") == old["vmUUID"] for item in active_vms),
        "old edge VM remains active after NodeClaim replacement",
    )
    active_fips = [item for item in api_get("network/ip_addresses") if active(item)]
    require(
        not any(
            item.get("name") == old["fipName"]
            or item.get("assigned_to") == old["vmUUID"]
            for item in active_fips
        ),
        "old edge FIP remains active or assigned after NodeClaim replacement",
    )


def prove_present(state: dict, kubeconfig: str, baseline: dict, probe: bool) -> dict:
    require_nlb_baseline(baseline)
    service = kubectl(kubeconfig, "-n", "default", "get", "service", SERVICE_NAME)
    require(service is not None, f"Service/{SERVICE_NAME} is absent")
    require_service_contract(service, state)
    nodes, claims = require_capacity_objects(state, kubeconfig, expect_ready_pods=True)
    endpoints = ready_endpoint_nodes(kubeconfig)
    node_names = sorted(node["metadata"]["name"] for node in nodes)
    require(endpoints == node_names, "Service Ready local endpoints do not equal the selected edge Nodes")
    proof_nodes, firewalls, vm_uuids = cloud_capacity(state, nodes, claims, require_service_firewall=True)
    ingress = service.get("status", {}).get("loadBalancer", {}).get("ingress", [])
    expected_ips = sorted(item["publicIP"] for item in proof_nodes)
    require(
        ingress == [{"ip": address, "ipMode": "Proxy"} for address in expected_ips],
        "Service public Proxy status does not exactly equal sorted eligible node FIPs",
    )
    datapath = require_datapath_contract(
        kubeconfig,
        service,
        state,
        [item["privateIP"] for item in proof_nodes],
    )
    firewall = service_firewall(service, firewalls, state["clusterName"], vm_uuids, assigned=True)
    proof = {
        "phase": "present",
        "serviceUID": service["metadata"]["uid"],
        "nodes": proof_nodes,
        "firewall": firewall,
        "datapath": datapath,
        "statusIPs": expected_ips,
    }
    if probe:
        proof["sourceIP"] = http_probe(proof, f"{state['clusterName']}-public-local")
        proof["udpProbes"] = udp_probe(
            proof, f"{state['clusterName']}-public-local-udp"
        )
    return proof


def prove_withdrawn(state: dict, kubeconfig: str, baseline: dict, anchor: dict) -> dict:
    require_nlb_baseline(baseline)
    service = kubectl(kubeconfig, "-n", "default", "get", "service", SERVICE_NAME)
    require(service is not None, f"Service/{SERVICE_NAME} is absent during endpoint withdrawal")
    require_service_contract(service, state)
    require(service.get("status", {}).get("loadBalancer", {}).get("ingress", []) == [], "Service retained public status without a Ready local endpoint")
    require_datapath_contract(kubeconfig, service, state, [])
    require(ready_endpoint_nodes(kubeconfig) == [], "Service retained a Ready local endpoint after scale-to-zero")
    nodes, claims = require_capacity_objects(state, kubeconfig, expect_ready_pods=False)
    proof_nodes, firewalls, vm_uuids = cloud_capacity(state, nodes, claims, require_service_firewall=False)
    service_firewall(service, firewalls, state["clusterName"], vm_uuids, assigned=False)
    require(
        [{key: item[key] for key in ("node", "nodeClaim", "vmUUID", "privateIP", "publicIP", "fipName")} for item in proof_nodes]
        == [{key: item[key] for key in ("node", "nodeClaim", "vmUUID", "privateIP", "publicIP", "fipName")} for item in anchor["nodes"]],
        "endpoint withdrawal changed edge VM or FIP identity",
    )
    return {"phase": "withdrawn", "nodes": proof_nodes}


def service_firewall_prefix(state: dict) -> str:
    uid = state.get("publicLocalServiceUID", "")
    require(isinstance(uid, str) and uid, "ownership journal lacks the public-local Service UID")
    cluster_hash = hashlib.sha256(state["clusterName"].encode()).hexdigest()[:8]
    return f"inlb-{cluster_hash}-{uid}-"


def prove_service_absent(state: dict, kubeconfig: str, baseline: dict, anchor: dict | None) -> dict:
    require_nlb_baseline(baseline)
    service = kubectl(kubeconfig, "-n", "default", "get", "service", SERVICE_NAME, "--ignore-not-found=true")
    require(service is None, f"Service/{SERVICE_NAME} still exists")
    uid = state.get("publicLocalServiceUID", "")
    require(isinstance(uid, str) and uid, "ownership journal lacks the public-local Service UID")
    require_datapath_absent(kubeconfig, "default", SERVICE_NAME, uid)
    prefix = service_firewall_prefix(state)
    firewalls = api_get("network/firewalls")
    require(
        not any(active(item) and effective_name(item).startswith(prefix) for item in firewalls),
        "public-local Service firewall remains after Service deletion",
    )
    nodes, claims = require_capacity_objects(state, kubeconfig, expect_ready_pods=True)
    proof_nodes, _, _ = cloud_capacity(state, nodes, claims, require_service_firewall=False)
    if anchor is not None:
        stable_keys = ("node", "nodeClaim", "vmUUID", "privateIP", "publicIP", "fipName")
        require(
            [{key: item[key] for key in stable_keys} for item in proof_nodes]
            == [{key: item[key] for key in stable_keys} for item in anchor["nodes"]],
            "Service cleanup moved or deleted a user-owned edge FIP/VM",
        )
    return {"phase": "service-absent", "nodes": proof_nodes}


def prove_absent(state: dict, kubeconfig: str, baseline: dict) -> dict:
    require_nlb_baseline(baseline)
    uid = state.get("publicLocalServiceUID", "")
    require(isinstance(uid, str) and uid, "ownership journal lacks the public-local Service UID")
    require_datapath_absent(kubeconfig, "default", SERVICE_NAME, uid)
    for kind, name, namespaced in (
        ("service", SERVICE_NAME, True),
        ("deployment", DEPLOYMENT_NAME, True),
        ("nodepool", state["publicLocalNodePoolName"], False),
        ("inspacenodeclass", state["publicLocalNodeClassName"], False),
    ):
        arguments = (["-n", "default"] if namespaced else []) + ["get", kind, name, "--ignore-not-found=true"]
        require(kubectl(kubeconfig, *arguments) is None, f"{kind}/{name} still exists")
    claims = kubectl(kubeconfig, "get", "nodeclaims", "-l", f"karpenter.sh/nodepool={state['publicLocalNodePoolName']}")
    nodes = kubectl(kubeconfig, "get", "nodes", "-l", f"karpenter.sh/nodepool={state['publicLocalNodePoolName']}")
    require(claims is not None and claims.get("items", []) == [], "public-local NodeClaims remain")
    require(nodes is not None and nodes.get("items", []) == [], "public-local Nodes remain")

    cluster = state["clusterName"]
    pool_name = state["publicLocalNodePoolName"]
    vm_prefix = f"{cluster}-karp-{pool_name}-"
    for vm in api_get("user-resource/vm/list"):
        if not active(vm):
            continue
        record = description(vm)
        require(
            not str(vm.get("name", "")).startswith(vm_prefix)
            and not (record.get("cluster") == cluster and str(record.get("nodeClaim", "")).startswith(pool_name + "-")),
            "public-local edge VM remains after NodePool deletion",
        )
    fip_prefix = f"karpenter-{pool_name}-"
    require(
        not any(active(item) and str(item.get("name", "")).startswith(fip_prefix) for item in api_get("network/ip_addresses")),
        "public-local edge FIP remains after NodePool deletion",
    )
    prefix = service_firewall_prefix(state)
    require(
        not any(active(item) and effective_name(item).startswith(prefix) for item in api_get("network/firewalls")),
        "public-local Service firewall remains after complete cleanup",
    )
    return {"phase": "absent"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument(
        "--expect",
        choices=("present", "withdrawn", "service-absent", "absent"),
        required=True,
    )
    parser.add_argument("--anchor")
    parser.add_argument("--probe-public", action="store_true")
    args = parser.parse_args()

    state = read_state(pathlib.Path(args.state))
    baseline = read_baseline(pathlib.Path(args.baseline))
    anchor = None
    if args.anchor:
        anchor = json.loads(pathlib.Path(args.anchor).read_text(encoding="utf-8"))
        require(isinstance(anchor, dict) and anchor.get("phase") == "present", "public-local anchor is invalid")

    if args.expect == "present":
        result = prove_present(state, args.kubeconfig, baseline, args.probe_public)
        if anchor is not None:
            require_replacement(anchor, result)
            result["replacementOf"] = anchor["nodes"][0]["nodeClaim"]
        record_known_cloud_identities(
            pathlib.Path(args.state),
            state,
            vm_uuids=[node["vmUUID"] for node in result["nodes"]],
            floating_ip_addresses=[node["publicIP"] for node in result["nodes"]],
        )
    elif args.expect == "withdrawn":
        require(anchor is not None, "withdrawn proof requires --anchor")
        result = prove_withdrawn(state, args.kubeconfig, baseline, anchor)
    elif args.expect == "service-absent":
        result = prove_service_absent(state, args.kubeconfig, baseline, anchor)
    else:
        result = prove_absent(state, args.kubeconfig, baseline)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
