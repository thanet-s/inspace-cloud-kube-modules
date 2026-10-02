#!/usr/bin/env python3
"""Regenerate the audited RKE2 bootstrap-cache pins for one RKE2 release.

Reads the release's public sha256sum-amd64.txt and
rke2-images-{core,ingress-nginx,cilium}.linux-amd64.txt assets, resolves each
image tag's top-level index digest with `docker buildx imagetools inspect
--raw`, and prints the Go values for
modules/cloud-provider/pkg/bootstrap/cache.go. With --check it instead exits
non-zero unless cache.go already pins exactly those values.

Needs Docker with buildx and public network access to GitHub and Docker Hub.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
CACHE_GO = ROOT / "modules/cloud-provider/pkg/bootstrap/cache.go"
LISTS = ("rke2-images-core", "rke2-images-ingress-nginx", "rke2-images-cilium")


def release_asset(version: str, name: str) -> str:
    url = (
        "https://github.com/rancher/rke2/releases/download/"
        f"{urllib.parse.quote(version, safe='')}/{name}"
    )
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read().decode()


def index_digest(image: str) -> str:
    raw = subprocess.run(
        ["docker", "buildx", "imagetools", "inspect", "--raw", image],
        check=True,
        capture_output=True,
    ).stdout
    manifest = json.loads(raw)
    platforms = {
        (entry.get("platform", {}).get("os"), entry.get("platform", {}).get("architecture"))
        for entry in manifest.get("manifests", [])
    }
    if ("linux", "amd64") not in platforms:
        raise SystemExit(f"{image} has no linux/amd64 manifest")
    return hashlib.sha256(raw).hexdigest()


def render(version: str) -> str:
    sums = release_asset(version, "sha256sum-amd64.txt")
    tarball = [
        line.split()[0]
        for line in sums.splitlines()
        if line.split()[1:] in (["rke2.linux-amd64.tar.gz"], ["./rke2.linux-amd64.tar.gz"])
    ]
    if len(tarball) != 1:
        raise SystemExit("sha256sum-amd64.txt does not list exactly one rke2.linux-amd64.tar.gz")
    core, ingress, cilium = (
        [line.strip() for line in release_asset(version, f"{name}.linux-amd64.txt").splitlines() if line.strip()]
        for name in LISTS
    )
    # cache.go keeps the two ingress-nginx images directly after mirrored-pause.
    pause = next(index for index, image in enumerate(core) if image.startswith("docker.io/rancher/mirrored-pause:"))
    images = core[: pause + 1] + ingress + core[pause + 1 :] + cilium
    lines = [
        f'\tbootstrapCacheRKE2Version = "{version}"',
        f'\tbootstrapCacheRKE2SHA256  = "{tarball[0]}"',
        "",
    ]
    for image in images:
        if not image.startswith("docker.io/rancher/"):
            raise SystemExit(f"unexpected non-rancher RKE2 image {image}")
        repository, tag = image.removeprefix("docker.io/").rsplit(":", 1)
        digest = index_digest(image)
        lines.append(f'\t{{source("{repository}", "{tag}", "{digest}"), "{repository}:{tag}"}},')
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version", help="exact RKE2 release, for example v1.36.5+rke2r1")
    parser.add_argument("--check", action="store_true", help="verify cache.go instead of printing")
    args = parser.parse_args()
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\d+)?\+rke2r\d+", args.version):
        parser.error("version must look like v1.36.5+rke2r1 or v1.37.0-rc1+rke2r1")
    rendered = render(args.version)
    if not args.check:
        sys.stdout.write(rendered)
        return 0
    source = CACHE_GO.read_text(encoding="utf-8").replace("\r\n", "\n")
    missing = [line for line in rendered.splitlines() if line and line not in source.splitlines()]
    for line in missing:
        print(f"cache.go lacks: {line.strip()}", file=sys.stderr)
    block = source.split("var rke2CacheImages = []cachedImage{\n", 1)[1].split("\n}\n", 1)[0]
    if block.count("{source(") != len([line for line in rendered.splitlines() if "{source(" in line]):
        print("cache.go RKE2 inventory has a different image count", file=sys.stderr)
        missing.append("count")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
