#!/usr/bin/env python3
"""Guard against unsafe in-place RKE2 control-plane version transitions."""

from __future__ import annotations

import re
import sys

VERSION_PATTERN = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:-rc(\d+))?\+rke2r(\d+)$")
# Pre-releases are refused as a target except the single audited release
# candidate pinned by the bootstrap cache
# (modules/cloud-provider/pkg/bootstrap/cache.go). Drop it when that pin moves
# to its GA release.
AUDITED_PRERELEASES = frozenset({"v1.36.5-rc2+rke2r1"})
# Every release candidate a published modules release ever pinned. Clusters
# installed on one must keep upgrading off it after the pin moves, so an entry
# is never removed; the pin refresh in DEVELOPMENT.md leaves this file alone.
RELEASED_PRERELEASES = frozenset({"v1.36.5-rc2+rke2r1"})
# Sorts a GA release after every release candidate of the same patch.
GA = 1 << 31


class UnsafeRKE2Transition(Exception):
    pass


def parse_version(value: str, prereleases: frozenset[str] | None = None) -> tuple[int, int, int, int, int]:
    match = VERSION_PATTERN.match(value)
    allowed = AUDITED_PRERELEASES if prereleases is None else prereleases
    if not match or (match.group(4) is not None and value not in allowed):
        raise UnsafeRKE2Transition(f"malformed or unaudited RKE2 version string {value!r}")
    major, minor, patch, candidate, build = match.groups()
    return int(major), int(minor), int(patch), GA if candidate is None else int(candidate), int(build)


def validate_transition(current: str, desired: str, forced: bool) -> None:
    c_major, c_minor, c_patch, c_candidate, _ = parse_version(current, AUDITED_PRERELEASES | RELEASED_PRERELEASES)
    d_major, d_minor, d_patch, d_candidate, _ = parse_version(desired)
    is_downgrade = (d_major, d_minor, d_patch, d_candidate) < (c_major, c_minor, c_patch, c_candidate)
    skips_minor = d_major != c_major or d_minor - c_minor > 1
    if is_downgrade and not forced:
        raise UnsafeRKE2Transition(
            f"refusing RKE2 downgrade from {current} to {desired}; export "
            "INSPACE_CONFIRM_RKE2_VERSION_SKIP=<cluster-name> to override"
        )
    if skips_minor and not forced:
        raise UnsafeRKE2Transition(
            f"refusing to skip RKE2 minor versions from {current} to {desired}; export "
            "INSPACE_CONFIRM_RKE2_VERSION_SKIP=<cluster-name> to override"
        )


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print("usage: validate_rke2_upgrade.py <current> <desired> <true|false>", file=sys.stderr)
        return 2
    current, desired, forced_raw = argv[1], argv[2], argv[3]
    if forced_raw not in ("true", "false"):
        print(f"forced flag must be 'true' or 'false', got {forced_raw!r}", file=sys.stderr)
        return 2
    try:
        validate_transition(current, desired, forced_raw == "true")
    except UnsafeRKE2Transition as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
