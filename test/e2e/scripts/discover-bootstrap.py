#!/usr/bin/env python3
"""Bind one reconciler result to the exact private-VIP bootstrap cloud graph."""

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
        headers={"apikey": os.environ["INSPACE_API_TOKEN"], "User-Agent": "inspace-rke2-e2e-bootstrap/1"},
    )
    with urllib.request.urlopen(request, timeout=60, context=ssl.create_default_context()) as response:
        return json.load(response)


VM_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def canonical_owned_vm_details(listed_vms, getter=api_get):
    """Replace sparse owned VM list rows with strict per-VM detail records."""
    details_by_name = {}
    for summary in listed_vms:
        if not isinstance(summary, dict):
            raise SystemExit("owned VM list contained a non-object record")
        name = summary.get("name")
        vm_uuid = summary.get("uuid")
        if not isinstance(name, str) or not isinstance(vm_uuid, str) or not VM_UUID_PATTERN.fullmatch(vm_uuid):
            raise SystemExit("owned VM list record lacks an exact name and valid UUID")
        if name in details_by_name:
            raise SystemExit(f"duplicate owned VM name {name!r} in list readback")
        query = urllib.parse.urlencode({"uuid": vm_uuid})
        detail = getter(f"user-resource/vm?{query}")
        if not isinstance(detail, dict):
            raise SystemExit(f"authoritative detail for VM {name!r} was not an object")
        if detail.get("uuid") != vm_uuid or detail.get("name") != name:
            raise SystemExit(f"authoritative detail identity for VM {name!r} does not match its list UUID/name")
        details_by_name[name] = detail
    return details_by_name


def require_public_ipv4(value: object, label: str) -> str:
    address = ipaddress.ip_address(str(value))
    if address.version != 4 or not address.is_global or address.is_loopback or address.is_multicast:
        raise SystemExit(f"{label} must be public IPv4")
    return str(address)


def require_private_ipv4(value: object, subnet: ipaddress.IPv4Network, label: str) -> str:
    address = ipaddress.ip_address(str(value))
    if address.version != 4 or not address.is_private or address not in subnet:
        raise SystemExit(f"{label} must be private IPv4 inside the configured VPC")
    return str(address)


def require_usable_fip(item: dict, label: str) -> str:
    if item.get("enabled") is not True or item.get("is_virtual") is not False or item.get("type") != "public":
        raise SystemExit(f"{label} must be an enabled non-virtual InSpace type=public FIP")
    return require_public_ipv4(item.get("address"), label)


def one(values, label: str):
    if len(values) != 1:
        raise SystemExit(f"expected exactly one {label}, found {len(values)}")
    return values[0]


def no_ports(rule) -> bool:
    return rule.get("port_start") is None and rule.get("port_end") is None


def validate_node_firewall(firewall, subnet: str, pod_cidr: str, vm_ids: set[str]) -> None:
    assignments = firewall.get("resources_assigned", [])
    if len(assignments) != 3 or {
        item.get("resource_uuid") for item in assignments if item.get("resource_type") == "vm"
    } != vm_ids or any(item.get("resource_type") != "vm" for item in assignments):
        raise SystemExit("node firewall must be assigned to exactly the three control-plane VMs")
    rules = firewall.get("rules", [])
    if len(rules) != 6:
        raise SystemExit("node firewall must contain exactly six private-routing/egress rules")
    for protocol in ("tcp", "udp", "icmp"):
        inbound = [rule for rule in rules if rule.get("direction") == "inbound" and rule.get("protocol") == protocol]
        outbound = [rule for rule in rules if rule.get("direction") == "outbound" and rule.get("protocol") == protocol]
        if len(inbound) != 1 or not no_ports(inbound[0]) or inbound[0].get("endpoint_spec_type") != "ip_prefixes" or len(inbound[0].get("endpoint_spec", [])) != 2 or set(inbound[0].get("endpoint_spec", [])) != {subnet, pod_cidr}:
            raise SystemExit(f"node firewall {protocol} ingress must cover only the VPC and native-routing pod CIDR")
        if len(outbound) != 1 or not no_ports(outbound[0]) or outbound[0].get("endpoint_spec_type") != "any" or outbound[0].get("endpoint_spec", []) not in ([], None):
            raise SystemExit(f"node firewall {protocol} egress must be unrestricted")
    for rule in rules:
        if rule.get("direction") == "inbound":
            for prefix in rule.get("endpoint_spec", []):
                if not ipaddress.ip_network(prefix, strict=False).is_private:
                    raise SystemExit("node firewall must have no public inbound source")


def validate_bastion_firewall(firewall, management_cidr: str, vm_uuid: str) -> None:
    assignments = firewall.get("resources_assigned", [])
    if assignments != [{"resource_type": "vm", "resource_uuid": vm_uuid}]:
        # API response objects may contain additional harmless display fields,
        # so compare the authoritative assignment keys independently as well.
        if len(assignments) != 1 or assignments[0].get("resource_type") != "vm" or assignments[0].get("resource_uuid") != vm_uuid:
            raise SystemExit("bastion firewall must be assigned only to the bastion VM")
    rules = firewall.get("rules", [])
    if len(rules) != 4:
        raise SystemExit("bastion firewall must contain only SSH ingress and three egress rules")
    inbound = [rule for rule in rules if rule.get("direction") == "inbound"]
    if len(inbound) != 1 or inbound[0].get("protocol") != "tcp" or inbound[0].get("port_start") != 22 or inbound[0].get("port_end") != 22 or inbound[0].get("endpoint_spec_type") != "ip_prefixes" or inbound[0].get("endpoint_spec") != [management_cidr]:
        raise SystemExit("bastion public ingress must be only management /32 TCP/22")
    for protocol in ("tcp", "udp", "icmp"):
        outbound = [rule for rule in rules if rule.get("direction") == "outbound" and rule.get("protocol") == protocol]
        if len(outbound) != 1 or not no_ports(outbound[0]) or outbound[0].get("endpoint_spec_type") != "any" or outbound[0].get("endpoint_spec", []) not in ([], None):
            raise SystemExit(f"bastion {protocol} egress must be unrestricted")


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
    parser.add_argument("--result", required=True)
    args = parser.parse_args()

    state_path = pathlib.Path(args.state)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    result = json.loads(pathlib.Path(args.result).read_text(encoding="utf-8"))
    if not isinstance(state, dict) or not isinstance(result, dict):
        raise SystemExit("state and reconciler result must be JSON objects")

    owner = state["owner"]
    network_uuid = os.environ["INSPACE_NETWORK_UUID"]
    vip = ipaddress.ip_address(os.environ["INSPACE_CONTROL_PLANE_VIP"])
    pool_start = ipaddress.ip_address(os.environ["INSPACE_PRIVATE_LOAD_BALANCER_POOL_START"])
    pool_stop = ipaddress.ip_address(os.environ["INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP"])
    network = api_get(f"network/network/{network_uuid}")
    if not isinstance(network, dict) or network.get("uuid") != network_uuid:
        raise SystemExit("configured VPC lookup was not authoritative")
    network_members = list(network.get("vm_uuids", []))
    network_member_ids = set(network_members)
    subnet = ipaddress.ip_network(network["subnet"], strict=False)
    if subnet.version != 4 or vip not in subnet or not vip.is_private:
        raise SystemExit("control-plane VIP must be private IPv4 inside the configured VPC")
    if (
        pool_start.version != 4
        or pool_stop.version != 4
        or not pool_start.is_private
        or not pool_stop.is_private
        or pool_start not in subnet
        or pool_stop not in subnet
        or pool_start in (subnet.network_address, subnet.broadcast_address)
        or pool_stop in (subnet.network_address, subnet.broadcast_address)
        or int(pool_start) > int(pool_stop)
        or int(pool_start) <= int(vip) <= int(pool_stop)
    ):
        raise SystemExit("private Service VIP range must be usable inside the VPC and exclude the control-plane VIP")

    def in_private_service_pool(value: object) -> bool:
        try:
            address = ipaddress.ip_address(str(value))
        except ValueError:
            return False
        return address.version == 4 and int(pool_start) <= int(address) <= int(pool_stop)

    vms = api_get("user-resource/vm/list")
    if not isinstance(vms, list):
        raise SystemExit("VM list was not an array")
    if any(
        (vm.get("network_uuid") == network_uuid or vm.get("uuid") in network_member_ids)
        and in_private_service_pool(vm.get("private_ipv4"))
        for vm in vms
    ):
        raise SystemExit("operator-reserved private Service VIP range collides with a VPC VM")
    expected_cp_names = [f"rke2-{owner}-cp-{index}" for index in range(3)]
    bastion_name = f"rke2-{owner}-bastion"
    listed_owned_vms = [vm for vm in vms if str(vm.get("name", "")).startswith(f"rke2-{owner}-")]
    if len(listed_owned_vms) != 4 or {vm.get("name") for vm in listed_owned_vms} != {*expected_cp_names, bastion_name}:
        raise SystemExit("expected exactly three control planes and one deterministic bastion")
    vm_by_name = canonical_owned_vm_details(listed_owned_vms)
    owned_vms = list(vm_by_name.values())
    result_cp_ids = result.get("controlPlaneVMs")
    if not isinstance(result_cp_ids, list) or len(result_cp_ids) != 3 or len(set(result_cp_ids)) != 3:
        raise SystemExit("reconciler result did not contain three unique control-plane UUIDs")
    if {vm_by_name[name].get("uuid") for name in expected_cp_names} != set(result_cp_ids):
        raise SystemExit("control-plane names and reconciler UUIDs are not a bijection")
    bastion = vm_by_name[bastion_name]
    if bastion.get("uuid") != result.get("bastionVMUUID"):
        raise SystemExit("bastion result UUID does not match the deterministic VM")
    root_disks = [disk for disk in bastion.get("storage", []) if disk.get("primary")]
    if (
        bastion.get("vcpu") != 1
        or bastion.get("memory") != 2048
        or bastion.get("os_name") != "ubuntu"
        or str(bastion.get("os_version")) != "24.04"
        or bastion.get("designated_pool_uuid") != os.environ["INSPACE_INTEL_HOST_POOL_UUID"]
        or bastion.get("network_uuid") != network_uuid
        or bastion.get("billing_account") != int(os.environ["INSPACE_BILLING_ACCOUNT_ID"])
        or re.fullmatch(
            rf"inspace-rke2-bastion/v1 owner={re.escape(owner)} spec=[0-9a-f]{{64}}",
            str(bastion.get("description", "")),
        ) is None
        or len(root_disks) != 1
        or root_disks[0].get("size") != 30
    ):
        raise SystemExit("bastion must be exact Ubuntu 24.04 / 1-vCPU / 2-GiB / 30-GiB / configured-pool shape")

    addresses = [item for item in api_get("network/ip_addresses") if not item.get("is_deleted", False)]
    expected_fip_names = {name + "-ip" for name in expected_cp_names} | {bastion_name + "-ip"}
    owned_fips = [item for item in addresses if str(item.get("name", "")).startswith(f"rke2-{owner}-")]
    if len(owned_fips) != 4 or {item.get("name") for item in owned_fips} != expected_fip_names:
        raise SystemExit("expected one exact egress FIP for each control plane and bastion")
    bootstrap_vm_ids = {vm["uuid"] for vm in owned_vms}
    assigned_to_bootstrap = [item for item in addresses if item.get("assigned_to") in bootstrap_vm_ids]
    if len(assigned_to_bootstrap) != 4 or {item.get("name") for item in assigned_to_bootstrap} != expected_fip_names:
        raise SystemExit("bootstrap VMs must have no additional or foreign-named FIP assignments")
    if any(item.get("assigned_to_resource_type") != "virtual_machine" for item in owned_fips):
        raise SystemExit("bootstrap FIPs must attach only to VMs, never a load balancer")
    fip_by_name = {item["name"]: item for item in owned_fips}

    control_planes = []
    private_addresses = set()
    public_addresses = set()
    for slot, name in enumerate(expected_cp_names):
        vm = vm_by_name[name]
        fip = fip_by_name[name + "-ip"]
        root_disks = [disk for disk in vm.get("storage", []) if disk.get("primary")]
        if (
            vm.get("vcpu") != 2
            or vm.get("memory") != 4096
            or vm.get("os_name") != "ubuntu"
            or str(vm.get("os_version")) != "24.04"
            or vm.get("designated_pool_uuid") != os.environ["INSPACE_INTEL_HOST_POOL_UUID"]
            or vm.get("network_uuid") != network_uuid
            or vm.get("billing_account") != int(os.environ["INSPACE_BILLING_ACCOUNT_ID"])
            or re.fullmatch(
                rf"inspace-rke2-cp/v2 owner={re.escape(owner)} slot={slot} spec=[0-9a-f]{{64}}",
                str(vm.get("description", "")),
            ) is None
            or len(root_disks) != 1
            or root_disks[0].get("size") != 30
        ):
            raise SystemExit(f"{name} must be exact Ubuntu 24.04 / 2-vCPU / 4-GiB / 30-GiB control-plane shape")
        if fip.get("assigned_to") != vm.get("uuid"):
            raise SystemExit(f"{name} FIP is not assigned to its exact VM")
        private_value = vm.get("private_ipv4") or fip.get("assigned_to_private_ip")
        private_ip = require_private_ipv4(private_value, subnet, f"{name} private address")
        public_ip = require_usable_fip(fip, f"{name} egress address")
        if vm.get("private_ipv4") and str(vm["private_ipv4"]) != private_ip:
            raise SystemExit(f"{name} VM and FIP private-address records disagree")
        if vm.get("public_ipv4") and str(vm["public_ipv4"]) != public_ip:
            raise SystemExit(f"{name} VM and FIP public-address records disagree")
        if fip.get("assigned_to_private_ip") and str(fip["assigned_to_private_ip"]) != private_ip:
            raise SystemExit(f"{name} FIP private-address readback disagrees with the VM")
        private_addresses.add(private_ip)
        public_addresses.add(public_ip)
        control_planes.append({
            "name": name,
            "uuid": vm["uuid"],
            "privateIPv4": private_ip,
            "publicIPv4": public_ip,
            "floatingIPName": fip["name"],
        })
    if len(private_addresses) != 3 or len(public_addresses) != 3 or str(vip) in private_addresses:
        raise SystemExit("control-plane private/public addresses and VIP must all be unique")

    bastion_fip = fip_by_name[bastion_name + "-ip"]
    if bastion_fip.get("assigned_to") != bastion.get("uuid"):
        raise SystemExit("bastion FIP is not assigned to the exact bastion VM")
    bastion_private = require_private_ipv4(
        bastion.get("private_ipv4") or bastion_fip.get("assigned_to_private_ip"), subnet, "bastion private address"
    )
    bastion_public = require_usable_fip(bastion_fip, "bastion public address")
    if bastion_private != str(result.get("bastionPrivateIPv4")) or bastion_public != str(result.get("bastionPublicIPv4")):
        raise SystemExit("bastion result addresses do not match authoritative cloud records")
    if bastion.get("public_ipv4") and str(bastion["public_ipv4"]) != bastion_public:
        raise SystemExit("bastion VM and FIP public-address records disagree")
    if bastion_fip.get("assigned_to_private_ip") and str(bastion_fip["assigned_to_private_ip"]) != bastion_private:
        raise SystemExit("bastion FIP private-address readback disagrees with the VM")
    if bastion_private in private_addresses or bastion_public in public_addresses or str(vip) == bastion_private:
        raise SystemExit("bastion, control planes, and VIP must use unique addresses")

    expected_vm_ids = bootstrap_vm_ids
    if any(network_members.count(vm_uuid) != 1 for vm_uuid in expected_vm_ids):
        raise SystemExit("all bootstrap VMs must be exact members of the configured VPC")

    active_load_balancers = [
        lb for lb in api_get("network/load_balancers")
        if not lb.get("is_deleted", False)
    ]
    if any(
        lb.get("network_uuid") == network_uuid and in_private_service_pool(lb.get("private_address"))
        for lb in active_load_balancers
    ):
        raise SystemExit("operator-reserved private Service VIP range collides with an active InSpace NLB")
    owned_load_balancers = [
        lb for lb in active_load_balancers
        if str(lb.get("display_name", "")).startswith((f"rke2-{owner}-", f"k3s-{owner}-"))
    ]
    if owned_load_balancers:
        raise SystemExit("private-VIP bootstrap must not create or adopt a control-plane load balancer")
    if any(
        item.get("assigned_to_resource_type") == "load_balancer"
        and str(item.get("name", "")).startswith((f"rke2-{owner}-", f"k3s-{owner}-"))
        for item in addresses
    ):
        raise SystemExit("private-VIP bootstrap must not create an API endpoint FIP")

    firewalls = [fw for fw in api_get("network/firewalls") if not fw.get("is_deleted", False)]
    owned_firewalls = [
        fw for fw in firewalls
        if str(fw.get("display_name", fw.get("name", ""))).startswith(f"rke2-{owner}-")
    ]
    if {fw.get("display_name", fw.get("name")) for fw in owned_firewalls} != {
        f"rke2-{owner}-nodes", f"rke2-{owner}-bastion"
    } or len(owned_firewalls) != 2:
        raise SystemExit("expected exactly the managed node and bastion firewalls")
    node_firewall = one(
        [fw for fw in firewalls if fw.get("display_name", fw.get("name")) == f"rke2-{owner}-nodes"],
        "managed node firewall",
    )
    bastion_firewall = one(
        [fw for fw in firewalls if fw.get("display_name", fw.get("name")) == f"rke2-{owner}-bastion"],
        "managed bastion firewall",
    )
    if node_firewall.get("uuid") != result.get("firewallUUID"):
        raise SystemExit("reconciler node firewall UUID does not match cloud state")
    if bastion_firewall.get("uuid") != result.get("bastionFirewallUUID"):
        raise SystemExit("reconciler bastion firewall UUID does not match cloud state")
    for vm_uuid in result_cp_ids:
        assigned_firewalls = [
            firewall.get("uuid")
            for firewall in firewalls
            if any(
                assignment.get("resource_type") == "vm" and assignment.get("resource_uuid") == vm_uuid
                for assignment in firewall.get("resources_assigned", [])
            )
        ]
        if assigned_firewalls != [node_firewall.get("uuid")]:
            raise SystemExit("each control plane must be attached only to the managed node firewall")
    bastion_assigned_firewalls = [
        firewall.get("uuid")
        for firewall in firewalls
        if any(
            assignment.get("resource_type") == "vm" and assignment.get("resource_uuid") == bastion.get("uuid")
            for assignment in firewall.get("resources_assigned", [])
        )
    ]
    if bastion_assigned_firewalls != [bastion_firewall.get("uuid")]:
        raise SystemExit("the bastion must be attached only to the managed bastion firewall")
    billing_account = int(os.environ["INSPACE_BILLING_ACCOUNT_ID"])
    if node_firewall.get("billing_account_id") != billing_account:
        raise SystemExit("node firewall lacks the exact billing-account identity")
    if bastion_firewall.get("billing_account_id") != billing_account:
        raise SystemExit("bastion firewall lacks the exact billing-account identity")
    # InSpace accepts firewall descriptions on create but omits them from the
    # authoritative create/list responses. A description is therefore only an
    # optional drift signal; exact names, account, rules, and assignments are
    # the ownership proof used above and below.
    node_description = node_firewall.get("description")
    if node_description not in (None, "", f"Managed RKE2 node firewall for {owner}"):
        raise SystemExit("node firewall has an unexpected description")
    bastion_description = bastion_firewall.get("description")
    if bastion_description not in (None, "", f"Managed RKE2 bastion firewall for {owner}"):
        raise SystemExit("bastion firewall has an unexpected description")
    validate_node_firewall(node_firewall, str(subnet), "10.42.0.0/16", set(result_cp_ids))
    validate_bastion_firewall(bastion_firewall, state["managementCIDR"], bastion["uuid"])

    state.update({
        "virtualIPv4": str(vip),
        "privateLoadBalancerPoolStart": str(pool_start),
        "privateLoadBalancerPoolStop": str(pool_stop),
        "privateEndpoint": result["privateControlPlaneEndpoint"],
        "privateRegistrationEndpoint": result["privateRegistrationEndpoint"],
        "controlPlaneVMs": result_cp_ids,
        "controlPlanes": control_planes,
        "controlPlanePrivateIPv4s": [item["privateIPv4"] for item in control_planes],
        "controlPlanePublicIPv4s": [item["publicIPv4"] for item in control_planes],
        "firewallUUID": node_firewall["uuid"],
        "bastionFirewallUUID": bastion_firewall["uuid"],
        "bastionVMUUID": bastion["uuid"],
        "bastionName": bastion_name,
        "bastionPrivateIPv4": bastion_private,
        "bastionPublicIPv4": bastion_public,
        "bastionFloatingIPName": bastion_fip["name"],
    })
    atomic_write(state_path, state)
    print(json.dumps({"controlPlanes": control_planes, "bastion": {
        "uuid": bastion["uuid"], "name": bastion_name,
        "privateIPv4": bastion_private, "publicIPv4": bastion_public,
    }}, sort_keys=True))


if __name__ == "__main__":
    main()
