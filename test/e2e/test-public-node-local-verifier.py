#!/usr/bin/env python3
"""Unit tests for public-node-local source-address normalization."""

import hashlib
import importlib.util
import ipaddress
import pathlib
import sys
import unittest
from unittest import mock


SCRIPT_DIRECTORY = pathlib.Path(__file__).resolve().parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIRECTORY))
SPEC = importlib.util.spec_from_file_location(
    "verify_public_node_local",
    SCRIPT_DIRECTORY / "verify-public-node-local.py",
)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class ParseRemoteAddressTests(unittest.TestCase):
    def test_accepts_plain_ipv4(self) -> None:
        self.assertEqual(
            VERIFIER.parse_remote_address("203.0.113.10"),
            ipaddress.ip_address("203.0.113.10"),
        )

    def test_normalizes_bracketed_ipv4_mapped_ipv6(self) -> None:
        self.assertEqual(
            VERIFIER.parse_remote_address("[::ffff:203.0.113.10]"),
            ipaddress.ip_address("203.0.113.10"),
        )

    def test_normalizes_unbracketed_ipv4_mapped_ipv6(self) -> None:
        self.assertEqual(
            VERIFIER.parse_remote_address("::ffff:203.0.113.10"),
            ipaddress.ip_address("203.0.113.10"),
        )

    def test_retains_native_ipv6_for_caller_policy(self) -> None:
        self.assertEqual(
            VERIFIER.parse_remote_address("2001:4860:4860::8888"),
            ipaddress.ip_address("2001:4860:4860::8888"),
        )

    def test_rejects_malformed_address(self) -> None:
        with self.assertRaisesRegex(SystemExit, "malformed client source"):
            VERIFIER.parse_remote_address("[not-an-address]")


class ReadyEndpointNodeTests(unittest.TestCase):
    def test_accepts_explicit_null_endpoints(self) -> None:
        with mock.patch.object(
            VERIFIER,
            "kubectl",
            return_value={"items": [{"endpoints": None}]},
        ):
            self.assertEqual(VERIFIER.ready_endpoint_nodes("/kubeconfig"), [])

    def test_rejects_non_array_endpoints(self) -> None:
        with mock.patch.object(
            VERIFIER,
            "kubectl",
            return_value={"items": [{"endpoints": {}}]},
        ):
            with self.assertRaisesRegex(SystemExit, "must be an array or null"):
                VERIFIER.ready_endpoint_nodes("/kubeconfig")

    def test_returns_ready_nonterminating_node_names(self) -> None:
        with mock.patch.object(
            VERIFIER,
            "kubectl",
            return_value={
                "items": [
                    {
                        "endpoints": [
                            {
                                "nodeName": "node-a",
                                "conditions": {
                                    "ready": True,
                                    "terminating": False,
                                },
                            },
                            {
                                "nodeName": "node-b",
                                "conditions": {"ready": False},
                            },
                        ]
                    }
                ]
            },
        ):
            self.assertEqual(
                VERIFIER.ready_endpoint_nodes("/kubeconfig"),
                ["node-a"],
            )


CLUSTER = "ci-rke2"
VM_A = "11111111-1111-4111-8111-111111111111"
VM_B = "22222222-2222-4222-8222-222222222222"
BILLING = 4242
WEB_UID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
RELAY_UID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def make_service(name, uid, ports, ranges=None, annotations=None):
    service = {
        "metadata": {
            "name": name,
            "uid": uid,
            "annotations": {"service.inspace.cloud/public-node-local-firewall-mode": "per-vm"},
        },
        "spec": {"ports": [{"protocol": protocol, "port": port} for protocol, port in ports]},
    }
    if ranges:
        service["spec"]["loadBalancerSourceRanges"] = ranges
    service["metadata"]["annotations"].update(annotations or {})
    return service


def make_rule(protocol, port, sources=None):
    return {
        "protocol": protocol, "direction": "inbound", "port_start": port, "port_end": port,
        "endpoint_spec_type": "ip_prefixes" if sources else "any",
        "endpoint_spec": list(sources or []),
    }


def make_vm_firewall(vm_uuid, rules, uuid="f-" + "0" * 34, assignments=None, description=None):
    return {
        "uuid": uuid,
        "display_name": VERIFIER.vm_firewall_name(CLUSTER, vm_uuid),
        "billing_account_id": BILLING,
        "description": description,
        "rules": rules,
        "resources_assigned": [{"resource_type": "vm", "resource_uuid": vm_uuid}]
        if assignments is None else assignments,
    }


def make_anchor(vm_uuid, firewall, policy_hash, extra=None):
    annotations = {
        VERIFIER.VM_ANCHOR_VM: vm_uuid,
        VERIFIER.VM_ANCHOR_UUID: firewall["uuid"],
        VERIFIER.VM_ANCHOR_APPLIED_HASH: policy_hash,
    }
    annotations.update(extra or {})
    return {
        "metadata": {
            "name": VERIFIER.VM_ANCHOR_PREFIX + vm_uuid,
            "labels": {
                VERIFIER.VM_ANCHOR_LABEL: "true",
                VERIFIER.VM_ANCHOR_CLUSTER_LABEL: CLUSTER,
            },
            "annotations": annotations,
        }
    }


class PerVMRuleKeyTests(unittest.TestCase):
    def test_policy_hash_is_the_sha256_of_the_sorted_canonical_keys(self) -> None:
        keys = ["udp|443|any|", "tcp|80|any|"]
        self.assertEqual(
            VERIFIER.vm_firewall_policy_hash(keys),
            hashlib.sha256(b"tcp|80|any|\nudp|443|any|").hexdigest(),
        )

    def test_policy_hash_matches_the_go_client_vector(self) -> None:
        # Value of client.NodeLoadBalancerVMFirewallSpecHash for these two rules.
        keys = VERIFIER.firewall_rule_keys([
            make_rule("udp", 443),
            make_rule("tcp", 1935, ["10.0.0.0/8", "1.1.1.0/24"]),
        ])
        self.assertEqual(
            VERIFIER.vm_firewall_policy_hash(keys),
            "5b833bfd49ba51111f1a85cd26b64fe6714a4e5be67e4d19440345ed87eee446",
        )

    def test_service_keys_carry_ports_and_sorted_source_ranges(self) -> None:
        service = make_service(
            "web", WEB_UID, [("TCP", 443), ("UDP", 443)], ranges=["10.0.0.0/8", "1.1.1.0/24"]
        )
        self.assertEqual(
            VERIFIER.service_rule_keys(service),
            ["tcp|443|ip_prefixes|1.1.1.0/24,10.0.0.0/8", "udp|443|ip_prefixes|1.1.1.0/24,10.0.0.0/8"],
        )

    def test_service_without_ranges_is_open_to_any(self) -> None:
        self.assertEqual(
            VERIFIER.service_rule_keys(make_service("web", WEB_UID, [("TCP", 80)])),
            ["tcp|80|any|"],
        )

    def test_union_of_two_services_is_sorted(self) -> None:
        union = VERIFIER.expected_vm_rule_keys([
            make_service("relay", RELAY_UID, [("TCP", 1935)]),
            make_service("web", WEB_UID, [("TCP", 80)]),
        ])
        self.assertEqual(union, ["tcp|1935|any|", "tcp|80|any|"])

    def test_union_rejects_one_port_claimed_twice(self) -> None:
        with self.assertRaisesRegex(SystemExit, "same public port"):
            VERIFIER.expected_vm_rule_keys([
                make_service("a", WEB_UID, [("TCP", 80)]),
                make_service("b", RELAY_UID, [("TCP", 80)], ranges=["10.0.0.0/8"]),
            ])

    def test_firewall_rule_keys_rejects_a_range_rule(self) -> None:
        rule = make_rule("tcp", 80)
        rule["port_end"] = 90
        with self.assertRaisesRegex(SystemExit, "not one inbound TCP/UDP port"):
            VERIFIER.firewall_rule_keys([rule])

    def test_firewall_rule_keys_rejects_a_duplicate(self) -> None:
        with self.assertRaisesRegex(SystemExit, "duplicate rule"):
            VERIFIER.firewall_rule_keys([make_rule("tcp", 80), make_rule("tcp", 80)])


class PerVMServiceTests(unittest.TestCase):
    def test_accepts_a_clean_per_vm_service(self) -> None:
        VERIFIER.require_per_vm_service(make_service("web", WEB_UID, [("TCP", 80)]))

    def test_rejects_a_service_without_the_mode_annotation(self) -> None:
        service = make_service("web", WEB_UID, [("TCP", 80)])
        del service["metadata"]["annotations"]["service.inspace.cloud/public-node-local-firewall-mode"]
        with self.assertRaisesRegex(SystemExit, "lacks"):
            VERIFIER.require_per_vm_service(service)

    def test_rejects_per_service_firewall_annotations(self) -> None:
        service = make_service(
            "web", WEB_UID, [("TCP", 80)],
            annotations={"service.inspace.cloud/node-lb-firewall-uuid": "f-1"},
        )
        with self.assertRaisesRegex(SystemExit, "per-Service firewall annotations"):
            VERIFIER.require_per_vm_service(service)

    def test_rejects_unresolved_per_vm_state(self) -> None:
        service = make_service(
            "web", WEB_UID, [("TCP", 80)],
            annotations={"service.inspace.cloud/vmfw-migration": "{}"},
        )
        with self.assertRaisesRegex(SystemExit, "unresolved per-VM firewall mutation state"):
            VERIFIER.require_per_vm_service(service)


class PerVMFirewallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.services = [
            make_service("web", WEB_UID, [("TCP", 80), ("UDP", 443)]),
            make_service("relay", RELAY_UID, [("TCP", 1935)], ranges=["10.0.0.0/8"]),
        ]
        self.rules = [
            make_rule("tcp", 80), make_rule("udp", 443), make_rule("tcp", 1935, ["10.0.0.0/8"]),
        ]
        self.hash = VERIFIER.vm_firewall_policy_hash(VERIFIER.firewall_rule_keys(self.rules))
        self.firewall = make_vm_firewall(VM_A, self.rules)
        self.anchor = make_anchor(VM_A, self.firewall, self.hash)

    def check(self, firewalls=None, anchors=None, services=None, vms=None):
        return VERIFIER.require_vm_firewalls(
            CLUSTER,
            vms or [VM_A],
            services or self.services,
            [self.firewall] if firewalls is None else firewalls,
            {VM_A: self.anchor} if anchors is None else anchors,
            BILLING,
        )

    def test_accepts_one_matching_firewall_and_anchor(self) -> None:
        proofs = self.check()
        self.assertEqual(proofs, [{
            "vmUUID": VM_A, "uuid": self.firewall["uuid"],
            "name": VERIFIER.vm_firewall_name(CLUSTER, VM_A), "hash": self.hash,
        }])

    def test_accepts_the_managed_description(self) -> None:
        self.firewall["description"] = VERIFIER.VM_FIREWALL_DESCRIPTION
        self.check()

    def test_rejects_a_missing_firewall(self) -> None:
        with self.assertRaisesRegex(SystemExit, "exactly one per-VM firewall, found 0"):
            self.check(firewalls=[])

    def test_rejects_two_firewalls_with_the_per_vm_name(self) -> None:
        duplicate = make_vm_firewall(VM_A, self.rules, uuid="f-" + "1" * 34)
        with self.assertRaisesRegex(SystemExit, "found 2"):
            self.check(firewalls=[self.firewall, duplicate])

    def test_rejects_a_firewall_assigned_to_another_vm_too(self) -> None:
        self.firewall["resources_assigned"].append({"resource_type": "vm", "resource_uuid": VM_B})
        with self.assertRaisesRegex(SystemExit, "not assigned to exactly that VM"):
            self.check()

    def test_rejects_rules_that_miss_a_service(self) -> None:
        with self.assertRaisesRegex(SystemExit, "exactly the rules of its Services"):
            self.check(services=self.services + [make_service("extra", "c" * 8 + "-cccc-4ccc-8ccc-cccccccccccc", [("TCP", 9000)])])

    def test_rejects_a_changed_source_range(self) -> None:
        self.services[1]["spec"]["loadBalancerSourceRanges"] = ["192.0.2.0/24"]
        with self.assertRaisesRegex(SystemExit, "exactly the rules of its Services"):
            self.check()

    def test_rejects_a_missing_anchor(self) -> None:
        with self.assertRaisesRegex(SystemExit, "no anchor ConfigMap"):
            self.check(anchors={VM_A: None})

    def test_rejects_an_anchor_hash_that_differs_from_the_firewall(self) -> None:
        self.anchor["metadata"]["annotations"][VERIFIER.VM_ANCHOR_APPLIED_HASH] = "0" * 64
        with self.assertRaisesRegex(SystemExit, "applied-hash"):
            self.check()

    def test_rejects_an_anchor_that_names_another_firewall(self) -> None:
        self.anchor["metadata"]["annotations"][VERIFIER.VM_ANCHOR_UUID] = "f-other"
        with self.assertRaisesRegex(SystemExit, "different firewall"):
            self.check()

    def test_rejects_an_anchor_with_unresolved_state(self) -> None:
        self.anchor["metadata"]["annotations"]["service.inspace.cloud/vmfw-pending-op"] = "put"
        with self.assertRaisesRegex(SystemExit, "unresolved mutation state"):
            self.check()

    def test_rejects_a_stray_per_service_firewall(self) -> None:
        cluster_hash = hashlib.sha256(CLUSTER.encode()).hexdigest()[:8]
        stray = {
            "uuid": "f-" + "2" * 34,
            "display_name": f"inlb-{cluster_hash}-{WEB_UID}-deadbeef",
        }
        with self.assertRaisesRegex(SystemExit, "still has a per-Service firewall"):
            self.check(firewalls=[self.firewall, stray])

    def test_two_vms_each_need_their_own_firewall(self) -> None:
        second = make_vm_firewall(VM_B, self.rules, uuid="f-" + "3" * 34)
        proofs = VERIFIER.require_vm_firewalls(
            CLUSTER, [VM_B, VM_A], self.services, [self.firewall, second],
            {VM_A: self.anchor, VM_B: make_anchor(VM_B, second, self.hash)}, BILLING,
        )
        self.assertEqual([proof["vmUUID"] for proof in proofs], [VM_A, VM_B])

    def test_no_vm_firewalls_passes_when_none_exist(self) -> None:
        VERIFIER.require_no_vm_firewalls(CLUSTER, [VM_A], [])

    def test_no_vm_firewalls_fails_when_one_remains(self) -> None:
        with self.assertRaisesRegex(SystemExit, "remains with no Service"):
            VERIFIER.require_no_vm_firewalls(CLUSTER, [VM_A], [self.firewall])


class ReplacementFirewallTests(unittest.TestCase):
    def per_vm(self, vm_uuid, uuid, policy_hash="h" * 64):
        return {"mode": "perVM", "vmFirewalls": [{"vmUUID": vm_uuid, "uuid": uuid, "name": "n", "hash": policy_hash}]}

    def test_per_vm_firewall_moves_to_the_new_vm(self) -> None:
        VERIFIER.require_replacement_firewall(self.per_vm(VM_A, "f1"), self.per_vm(VM_B, "f2"))

    def test_per_vm_firewall_on_the_same_vm_is_not_a_replacement(self) -> None:
        with self.assertRaisesRegex(SystemExit, "did not move the per-VM firewall"):
            VERIFIER.require_replacement_firewall(self.per_vm(VM_A, "f1"), self.per_vm(VM_A, "f1"))

    def test_per_vm_policy_must_survive_the_replacement(self) -> None:
        with self.assertRaisesRegex(SystemExit, "same policy"):
            VERIFIER.require_replacement_firewall(
                self.per_vm(VM_A, "f1", "a" * 64), self.per_vm(VM_B, "f2", "b" * 64))

    def test_per_service_firewall_must_not_change(self) -> None:
        same = {"uuid": "f1", "name": "inlb-x", "hash": "deadbeef"}
        VERIFIER.require_replacement_firewall(same, dict(same))
        with self.assertRaisesRegex(SystemExit, "changed the Service-owned firewall identity"):
            VERIFIER.require_replacement_firewall(same, {**same, "uuid": "f2"})

    def test_leaving_per_vm_mode_fails(self) -> None:
        with self.assertRaisesRegex(SystemExit, "left the per-VM firewall mode"):
            VERIFIER.require_replacement_firewall(self.per_vm(VM_A, "f1"), {"uuid": "f1"})


class NoPerVMStateTests(unittest.TestCase):
    def test_passes_when_nothing_remains(self) -> None:
        VERIFIER.require_no_per_vm_state(CLUSTER, [], [{"display_name": "inlb-unrelated"}])

    def test_fails_while_an_anchor_remains(self) -> None:
        anchor = make_anchor(VM_A, make_vm_firewall(VM_A, []), "h")
        with self.assertRaisesRegex(SystemExit, "anchor ConfigMaps remain"):
            VERIFIER.require_no_per_vm_state(CLUSTER, [anchor], [])

    def test_fails_while_a_per_vm_firewall_remains(self) -> None:
        with self.assertRaisesRegex(SystemExit, "per-VM firewalls remain"):
            VERIFIER.require_no_per_vm_state(CLUSTER, [], [make_vm_firewall(VM_A, [])])


class PerServiceModeStillWorksTests(unittest.TestCase):
    def test_default_mode_is_per_service(self) -> None:
        self.assertEqual(VERIFIER.MODE_PER_SERVICE, "perService")
        self.assertEqual(VERIFIER.MODE_PER_VM, "perVM")

    def test_per_service_firewall_identity_is_unchanged(self) -> None:
        name, policy_hash = VERIFIER.service_firewall_identity(CLUSTER, WEB_UID)
        self.assertTrue(name.startswith("inlb-"))
        self.assertTrue(name.endswith("-" + policy_hash))
        self.assertEqual(len(policy_hash), 8)


if __name__ == "__main__":
    unittest.main()
