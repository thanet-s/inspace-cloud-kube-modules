#!/usr/bin/env python3
"""Prove private Cilium Services own no cloud resources and public NLB ownership is exact."""

import argparse
import ipaddress
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
        headers={"apikey": os.environ["INSPACE_API_TOKEN"], "User-Agent": "inspace-rke2-e2e-service/1"},
    )
    with urllib.request.urlopen(request, timeout=60, context=ssl.create_default_context()) as response:
        value = json.load(response)
    if not isinstance(value, list):
        raise SystemExit(f"{path} did not return an array")
    return value


def require_nonvirtual_flag(value: object) -> None:
    """Accept only the two raw API encodings for a non-virtual address."""
    if value is not None and value is not False:
        raise SystemExit("public Service FIP must be a non-virtual InSpace address")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--public", choices=("present", "absent"), required=True)
    args = parser.parse_args()

    state = json.loads(pathlib.Path(args.state).read_text(encoding="utf-8"))
    public_lb_name = state.get("serviceLoadBalancerName", "")
    public_fip_name = state.get("serviceFloatingIPName", "")
    private_lb_names = set(state.get("privateServiceLoadBalancerNames", []))
    private_fip_names = set(state.get("privateServiceFloatingIPNames", []))
    if not public_lb_name or not public_fip_name or len(private_lb_names) != 2 or len(private_fip_names) != 2:
        raise SystemExit("workload ownership journal lacks the exact three Service identities")

    active_lbs = [lb for lb in api_get("network/load_balancers") if not lb.get("is_deleted", False)]
    active_fips = [ip for ip in api_get("network/ip_addresses") if not ip.get("is_deleted", False)]
    if any(lb.get("display_name") in private_lb_names for lb in active_lbs):
        raise SystemExit("a private Cilium L2 Service unexpectedly owns an InSpace NLB")
    if any(ip.get("name") in private_fip_names for ip in active_fips):
        raise SystemExit("a private Cilium L2 Service unexpectedly owns an InSpace FIP")

    public_lbs = [lb for lb in active_lbs if lb.get("display_name") == public_lb_name]
    public_fips = [ip for ip in active_fips if ip.get("name") == public_fip_name]
    if args.public == "absent":
        if public_lbs or public_fips:
            raise SystemExit("public Service NLB/FIP cleanup has not completed")
        print(json.dumps({"public": "absent"}, sort_keys=True))
        return

    if len(public_lbs) != 1 or len(public_fips) != 1:
        raise SystemExit("public Service must own exactly one InSpace NLB and one FIP")
    load_balancer = public_lbs[0]
    floating_ip = public_fips[0]
    if load_balancer.get("network_uuid") != os.environ["INSPACE_NETWORK_UUID"]:
        raise SystemExit("public Service NLB is outside the configured VPC")
    control_plane_targets = state.get("controlPlaneVMs", [])
    worker_records = state.get("workerVMs", [])
    if (
        not isinstance(control_plane_targets, list)
        or len(control_plane_targets) != 3
        or any(not isinstance(value, str) or not value for value in control_plane_targets)
        or not isinstance(worker_records, list)
        or len(worker_records) != 1
        or not isinstance(worker_records[0], dict)
        or not isinstance(worker_records[0].get("uuid"), str)
        or not worker_records[0]["uuid"]
    ):
        raise SystemExit("workload journal lacks exactly three control-plane and one worker target UUIDs")
    expected_targets = set(control_plane_targets) | {worker_records[0]["uuid"]}
    if len(expected_targets) != 4:
        raise SystemExit("public Service target journal contains duplicate VM UUIDs")
    targets = load_balancer.get("targets")
    if (
        not isinstance(targets, list)
        or len(targets) != 4
        or any(not isinstance(target, dict) or target.get("target_type") != "vm" for target in targets)
        or {target.get("target_uuid") for target in targets} != expected_targets
    ):
        raise SystemExit("public Service NLB targets must be exactly three control planes and one worker")
    forwarding_rules = load_balancer.get("forwarding_rules")
    if (
        not isinstance(forwarding_rules, list)
        or len(forwarding_rules) != 1
        or not isinstance(forwarding_rules[0], dict)
        or forwarding_rules[0].get("protocol") != "TCP"
        or forwarding_rules[0].get("source_port") != 80
        or forwarding_rules[0].get("target_port") != 30080
    ):
        raise SystemExit("public Service NLB must own exactly one TCP 80-to-30080 forwarding rule")
    private_address = ipaddress.ip_address(str(load_balancer.get("private_address")))
    control_plane_vip = ipaddress.ip_address(str(state.get("virtualIPv4")))
    start = ipaddress.ip_address(os.environ["INSPACE_PRIVATE_LOAD_BALANCER_POOL_START"])
    stop = ipaddress.ip_address(os.environ["INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP"])
    if (
        private_address.version != 4
        or not private_address.is_private
        or private_address == control_plane_vip
        or int(start) <= int(private_address) <= int(stop)
    ):
        raise SystemExit("public InSpace NLB private address collides with the control-plane VIP or reserved Cilium pool")
    public_address = ipaddress.ip_address(str(floating_ip.get("address")))
    require_nonvirtual_flag(floating_ip.get("is_virtual"))
    if (
        public_address.version != 4
        or not public_address.is_global
        or floating_ip.get("enabled") is not True
        or floating_ip.get("type") != "public"
        or floating_ip.get("assigned_to") != load_balancer.get("uuid")
        or floating_ip.get("assigned_to_resource_type") != "load_balancer"
    ):
        raise SystemExit("public Service FIP is not exact enabled public NLB ownership")
    print(json.dumps({
        "loadBalancerUUID": load_balancer.get("uuid"),
        "privateIPv4": str(private_address),
        "publicIPv4": str(public_address),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
