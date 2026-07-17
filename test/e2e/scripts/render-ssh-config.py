#!/usr/bin/env python3
"""Render the private-node SSH topology from the fail-closed ownership journal."""

import argparse
import ipaddress
import json
import os
import pathlib
import re

from durable_io import atomic_write_text


USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def quote(value: object) -> str:
    text = str(value)
    if not text or any(character in text for character in "\r\n\0"):
        raise SystemExit("SSH configuration values must be non-empty single-line strings")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def ip(value: object, public: bool) -> str:
    address = ipaddress.ip_address(str(value))
    if address.version != 4 or address.is_loopback or address.is_multicast:
        raise SystemExit("SSH addresses must be IPv4")
    if public and address.is_private:
        raise SystemExit("bastion SSH address must be public")
    if not public and not address.is_private:
        raise SystemExit("node SSH addresses must be private")
    return str(address)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    state_path = pathlib.Path(args.state)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    user = state.get("sshUsername")
    if not isinstance(user, str) or not USER.fullmatch(user):
        raise SystemExit("ownership journal contains an invalid SSH username")
    state_dir = state_path.parent
    identity = os.environ["E2E_PRIVATE_KEY"]
    bastion_public = ip(state["bastionPublicIPv4"], public=True)

    lines = [
        "Host e2e-bastion",
        f"  HostName {bastion_public}",
        f"  HostKeyAlias {bastion_public}",
        f"  User {user}",
        f"  IdentityFile {quote(identity)}",
        "  IdentitiesOnly yes",
        "  BatchMode yes",
        f"  UserKnownHostsFile {quote(state_dir / 'known-hosts-bastion')}",
        "  StrictHostKeyChecking yes",
        "  ConnectTimeout 10",
        "  ServerAliveInterval 5",
        "  ServerAliveCountMax 3",
        "",
    ]
    nodes = list(state.get("controlPlanes", []))
    workers = state.get("workerVMs", [])
    if isinstance(workers, list):
        nodes.extend(workers)
    for index, node in enumerate(nodes):
        alias = f"rke2-cp-{index + 1:02d}" if index < len(state.get("controlPlanes", [])) else "rke2-worker-01"
        private = ip(node["privateIPv4"] if "privateIPv4" in node else node["internalIPv4"], public=False)
        known_hosts = state_dir / (f"known-hosts-cp-{index}" if index < len(state.get("controlPlanes", [])) else "known-hosts-worker")
        lines.extend([
            f"Host {alias}",
            f"  HostName {private}",
            f"  HostKeyAlias {private}",
            f"  User {user}",
            f"  IdentityFile {quote(identity)}",
            "  IdentitiesOnly yes",
            "  BatchMode yes",
            "  ProxyJump e2e-bastion",
            f"  UserKnownHostsFile {quote(known_hosts)}",
            "  StrictHostKeyChecking yes",
            "  ConnectTimeout 10",
            "  ServerAliveInterval 5",
            "  ServerAliveCountMax 3",
            "",
        ])
    atomic_write_text(pathlib.Path(args.output), "\n".join(lines))


if __name__ == "__main__":
    main()
