#!/usr/bin/env python3
"""Guard against unsafe in-place RKE2 control-plane version transitions."""

from __future__ import annotations

import re
import sys

VERSION_PATTERN = re.compile(r"^v(\d+)\.(\d+)\.(\d+)\+rke2r(\d+)$")


class UnsafeRKE2Transition(Exception):
    pass


def parse_version(value: str) -> tuple[int, int, int, int]:
    match = VERSION_PATTERN.match(value)
    if not match:
        raise UnsafeRKE2Transition(f"malformed RKE2 version string {value!r}")
    major, minor, patch, build = (int(part) for part in match.groups())
    return major, minor, patch, build


def validate_transition(current: str, desired: str, forced: bool) -> None:
    c_major, c_minor, c_patch, _ = parse_version(current)
    d_major, d_minor, d_patch, _ = parse_version(desired)
    is_downgrade = (d_major, d_minor, d_patch) < (c_major, c_minor, c_patch)
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
