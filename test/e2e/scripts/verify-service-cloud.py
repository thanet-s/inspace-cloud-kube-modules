#!/usr/bin/env python3
"""Prove private Cilium Services own no cloud resources and public NLB ownership is exact."""

import argparse
import ipaddress
import json
import os
import pathlib
import ssl
import stat
import urllib.request


IMMUTABLE_INVENTORY_KEYS = {"vms", "firewalls", "floatingIPs", "loadBalancers", "disks"}


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


def active(item: dict) -> bool:
    return item.get("is_deleted") is not True and str(item.get("status", "")).lower() != "deleted"


def immutable_load_balancer_baseline(path: pathlib.Path) -> list[str]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise SystemExit("immutable account baseline inventory is absent")
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit("immutable account baseline inventory must be a mode-0600 regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"immutable account baseline inventory is unreadable: {error}")
    if not isinstance(value, dict) or set(value) != IMMUTABLE_INVENTORY_KEYS:
        raise SystemExit("immutable account baseline inventory has an unexpected schema")
    identities = value.get("loadBalancers")
    if (
        not isinstance(identities, list)
        or any(not isinstance(identity, str) or not identity for identity in identities)
        or identities != sorted(set(identities))
    ):
        raise SystemExit("immutable account NLB baseline is invalid")
    return identities


def require_exact_load_balancer_inventory(
    load_balancers: list[dict],
    immutable_baseline_path: pathlib.Path,
    allowed_paid_nlb_uuid: str | None = None,
) -> None:
    baseline = immutable_load_balancer_baseline(immutable_baseline_path)
    identities = []
    for load_balancer in load_balancers:
        if not isinstance(load_balancer, dict):
            raise SystemExit("load-balancer list contains a non-object")
        if not active(load_balancer):
            continue
        identity = load_balancer.get("uuid")
        if not isinstance(identity, str) or not identity:
            raise SystemExit("active load balancer lacks a stable UUID")
        identities.append(identity)
    if len(identities) != len(set(identities)):
        raise SystemExit("active load-balancer inventory contains duplicate UUIDs")

    expected = list(baseline)
    if allowed_paid_nlb_uuid is not None:
        if not isinstance(allowed_paid_nlb_uuid, str) or not allowed_paid_nlb_uuid:
            raise SystemExit("paid public Service NLB lacks a stable UUID")
        if allowed_paid_nlb_uuid in baseline:
            raise SystemExit("paid public Service NLB UUID already exists in the immutable account baseline")
        expected.append(allowed_paid_nlb_uuid)
    expected.sort()
    if sorted(identities) != expected:
        expected_scope = "the immutable pre-mutation account baseline"
        if allowed_paid_nlb_uuid is not None:
            expected_scope += " plus the exact paid public Service NLB"
        raise SystemExit(
            f"active InSpace NLB UUIDs differ from {expected_scope}: "
            f"current={sorted(identities)} expected={expected}"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--immutable-baseline", required=True)
    parser.add_argument("--public", choices=("present", "absent"), required=True)
    parser.add_argument(
        "--targets",
        choices=("ready", "empty"),
        default="ready",
        help="expected public NLB target state",
    )
    args = parser.parse_args()

    state = json.loads(pathlib.Path(args.state).read_text(encoding="utf-8"))
    public_lb_name = state.get("serviceLoadBalancerName", "")
    public_fip_name = state.get("serviceFloatingIPName", "")
    raw_private_lb_names = state.get("privateServiceLoadBalancerNames", [])
    raw_private_fip_names = state.get("privateServiceFloatingIPNames", [])
    if (
        not isinstance(raw_private_lb_names, list)
        or any(not isinstance(name, str) or not name for name in raw_private_lb_names)
        or len(raw_private_lb_names) != len(set(raw_private_lb_names))
        or not isinstance(raw_private_fip_names, list)
        or any(not isinstance(name, str) or not name for name in raw_private_fip_names)
        or len(raw_private_fip_names) != len(set(raw_private_fip_names))
    ):
        raise SystemExit("workload ownership journal contains invalid private Service identities")
    private_lb_names = set(raw_private_lb_names)
    private_fip_names = set(raw_private_fip_names)

    all_lbs = api_get("network/load_balancers")
    active_lbs = [lb for lb in all_lbs if isinstance(lb, dict) and active(lb)]
    active_fips = [ip for ip in api_get("network/ip_addresses") if isinstance(ip, dict) and active(ip)]
    if any(lb.get("display_name") in private_lb_names for lb in active_lbs):
        raise SystemExit("a private Cilium L2 Service unexpectedly owns an InSpace NLB")
    if any(ip.get("name") in private_fip_names for ip in active_fips):
        raise SystemExit("a private Cilium L2 Service unexpectedly owns an InSpace FIP")

    public_lbs = [lb for lb in active_lbs if public_lb_name and lb.get("display_name") == public_lb_name]
    public_fips = [ip for ip in active_fips if public_fip_name and ip.get("name") == public_fip_name]
    if args.public == "absent":
        if public_lbs or public_fips:
            raise SystemExit("public Service NLB/FIP cleanup has not completed")
        require_exact_load_balancer_inventory(
            all_lbs,
            pathlib.Path(args.immutable_baseline),
        )
        print(json.dumps({"public": "absent"}, sort_keys=True))
        return

    if not public_lb_name or not public_fip_name or len(private_lb_names) != 2 or len(private_fip_names) != 2:
        raise SystemExit("workload ownership journal lacks the exact three Service identities")
    if len(public_lbs) != 1 or len(public_fips) != 1:
        raise SystemExit("public Service must own exactly one InSpace NLB and one FIP")
    load_balancer = public_lbs[0]
    floating_ip = public_fips[0]
    require_exact_load_balancer_inventory(
        all_lbs,
        pathlib.Path(args.immutable_baseline),
        load_balancer.get("uuid"),
    )
    if load_balancer.get("network_uuid") != os.environ["INSPACE_NETWORK_UUID"]:
        raise SystemExit("public Service NLB is outside the configured VPC")
    worker_records = state.get("workerVMs", [])
    if (
        not isinstance(worker_records, list)
        or len(worker_records) != 1
        or not isinstance(worker_records[0], dict)
        or not isinstance(worker_records[0].get("uuid"), str)
        or not worker_records[0]["uuid"]
    ):
        raise SystemExit("workload journal lacks the exact Karpenter worker target UUID")
    expected_targets = {worker_records[0]["uuid"]} if args.targets == "ready" else set()
    targets = load_balancer.get("targets")
    if (
        not isinstance(targets, list)
        or len(targets) != len(expected_targets)
        or any(not isinstance(target, dict) or target.get("target_type") != "vm" for target in targets)
        or {target.get("target_uuid") for target in targets} != expected_targets
    ):
        if args.targets == "ready":
            raise SystemExit("public Service NLB target must be exactly the eligible Ready worker")
        raise SystemExit("public Service NLB targets must be empty without an eligible Ready target")
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
