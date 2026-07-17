#!/usr/bin/env python3
"""Durably merge exact cloud object identities into the E2E ownership journal."""

from __future__ import annotations

import ipaddress
import pathlib
import stat
import uuid
from collections.abc import Iterable

from durable_io import atomic_write_json, sync_file


IDENTITY_FIELDS = {
    "knownVMUUIDs": "uuid",
    "knownDiskUUIDs": "uuid",
    "knownLoadBalancerUUIDs": "uuid",
    "knownFloatingIPAddresses": "ip",
}


def _canonical(value: object, kind: str, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SystemExit(f"{label} is empty or not text")
    try:
        parsed = uuid.UUID(value) if kind == "uuid" else ipaddress.ip_address(value)
    except (ValueError, AttributeError) as error:
        raise SystemExit(f"{label} is malformed") from error
    canonical = str(parsed)
    if canonical != value:
        raise SystemExit(f"{label} is not canonical")
    return value


def record_known_cloud_identities(
    path: pathlib.Path,
    state: dict,
    *,
    vm_uuids: Iterable[str] = (),
    disk_uuids: Iterable[str] = (),
    load_balancer_uuids: Iterable[str] = (),
    floating_ip_addresses: Iterable[str] = (),
) -> None:
    """Merge exact identities without ever deleting an earlier ownership fact."""
    if not isinstance(state, dict):
        raise SystemExit("ownership journal must contain an object")
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise SystemExit("ownership journal must be a mode-0600 regular file")
    additions = {
        "knownVMUUIDs": list(vm_uuids),
        "knownDiskUUIDs": list(disk_uuids),
        "knownLoadBalancerUUIDs": list(load_balancer_uuids),
        "knownFloatingIPAddresses": list(floating_ip_addresses),
    }
    changed = False
    for field, kind in IDENTITY_FIELDS.items():
        current = state.get(field, [])
        if not isinstance(current, list):
            raise SystemExit(f"ownership journal {field} must be an array")
        values = {
            _canonical(value, kind, f"ownership journal {field}")
            for value in current
        }
        values.update(
            _canonical(value, kind, f"new ownership {field}")
            for value in additions[field]
        )
        merged = sorted(values)
        if current != merged:
            state[field] = merged
            changed = True
    if changed:
        atomic_write_json(path, state)
    else:
        # The identity was already journaled, but the verifier/delete ordering
        # still treats this call as its durability barrier.
        sync_file(path)
