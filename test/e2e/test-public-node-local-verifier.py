#!/usr/bin/env python3
"""Unit tests for public-node-local source-address normalization."""

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


if __name__ == "__main__":
    unittest.main()
