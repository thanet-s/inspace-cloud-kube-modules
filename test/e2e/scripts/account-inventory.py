#!/usr/bin/env python3
"""Capture/compare every API-visible billable resource in the isolated E2E account."""

import argparse
import json
import os
import pathlib
import ssl
import stat
import tempfile
import urllib.request


RESOURCE_PATHS = {
    "vms": ("user-resource/vm/list", "uuid"),
    "firewalls": ("network/firewalls", "uuid"),
    "floatingIPs": ("network/ip_addresses", "address"),
    "loadBalancers": ("network/load_balancers", "uuid"),
    "disks": ("storage/disks", "uuid"),
}


def api_get(path: str):
    base = os.environ["INSPACE_API_URL"].rstrip("/")
    location = os.environ["INSPACE_LOCATION"]
    request = urllib.request.Request(
        f"{base}/v1/{location}/{path}",
        headers={"apikey": os.environ["INSPACE_API_TOKEN"], "User-Agent": "inspace-rke2-e2e-inventory/1"},
    )
    with urllib.request.urlopen(request, timeout=60, context=ssl.create_default_context()) as response:
        value = json.load(response)
    if not isinstance(value, list):
        raise SystemExit(f"{path} did not return an array")
    return value


def active(item: dict) -> bool:
    return item.get("is_deleted") is not True and str(item.get("status", "")).lower() != "deleted"


def inventory() -> dict[str, list[str]]:
    result = {}
    for name, (path, identity_field) in RESOURCE_PATHS.items():
        identities = []
        for item in api_get(path):
            if not isinstance(item, dict):
                raise SystemExit(f"{path} returned a non-object resource item")
            if not active(item):
                continue
            identity = item.get(identity_field)
            if not isinstance(identity, str) or not identity.strip():
                raise SystemExit(f"active {name} item has no stable {identity_field}")
            identities.append(identity)
        if len(identities) != len(set(identities)):
            raise SystemExit(f"active {name} inventory contains duplicate identities")
        result[name] = sorted(identities)
    return result


def atomic_write(path: pathlib.Path, value: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
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


def read_baseline(path: pathlib.Path) -> dict:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit("baseline inventory must be a mode-0600 regular file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != set(RESOURCE_PATHS):
        raise SystemExit("baseline inventory has an unexpected schema")
    for name, identities in value.items():
        if (
            not isinstance(identities, list)
            or any(not isinstance(item, str) or not item.strip() for item in identities)
            or identities != sorted(set(identities))
        ):
            raise SystemExit(f"baseline inventory {name} is invalid")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    capture = subparsers.add_parser("capture")
    capture.add_argument("--output", required=True)
    compare = subparsers.add_parser("compare")
    compare.add_argument("--baseline", required=True)
    args = parser.parse_args()

    current = inventory()
    if args.action == "capture":
        output = pathlib.Path(args.output)
        if output.exists():
            raise SystemExit("refusing to replace an existing baseline inventory")
        atomic_write(output, current)
        print(json.dumps({"captured": True, "counts": {key: len(value) for key, value in current.items()}}, sort_keys=True))
        return

    baseline = read_baseline(pathlib.Path(args.baseline))
    extra = {key: sorted(set(current[key]) - set(baseline[key])) for key in RESOURCE_PATHS}
    missing = {key: sorted(set(baseline[key]) - set(current[key])) for key in RESOURCE_PATHS}
    difference_count = sum(len(value) for value in extra.values()) + sum(len(value) for value in missing.values())
    result = {"matches": difference_count == 0, "differenceCount": difference_count, "extra": extra, "missing": missing}
    print(json.dumps(result, sort_keys=True))
    if difference_count != 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
