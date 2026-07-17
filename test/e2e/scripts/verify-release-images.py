#!/usr/bin/env python3
"""Bind destructive E2E to one immutable source, image, and Helm artifact set."""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import http.client
import json
import os
import pathlib
import re
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from durable_io import atomic_write_bytes, atomic_write_json


REPOSITORY = "thanet-s/inspace-cloud-kube-modules"
REPOSITORY_URL = f"https://github.com/{REPOSITORY}"
SCHEMA = "inspace-e2e-release-artifacts-v2"
IMAGE_NAMES = (
    "inspace-cloud-controller-manager",
    "inspace-csi-driver",
    "karpenter-provider-inspace",
)
ENV_PREFIXES = {
    "inspace-cloud-controller-manager": "INSPACE_E2E_CCM",
    "inspace-csi-driver": "INSPACE_E2E_CSI",
    "karpenter-provider-inspace": "INSPACE_E2E_KARPENTER",
}
CHART_NAMES = (
    "inspace-cloud-kube-modules-crds",
    "inspace-cloud-kube-modules",
)
CHART_ENV_PREFIXES = {
    "inspace-cloud-kube-modules-crds": "INSPACE_E2E_CRDS_CHART",
    "inspace-cloud-kube-modules": "INSPACE_E2E_MODULES_CHART",
}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
RUN_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,22}[a-z0-9])?$")
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_CHECKSUM_BYTES = 4096
MAX_CHART_BYTES = 32 * 1024 * 1024
MAX_IMAGE_RECORD_BYTES = 4096
ALLOWED_RELEASE_REDIRECT_HOSTS = {
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
}
RETRYABLE_HTTP_STATUSES = {408, 429, 500, 502, 503, 504}


class ReleaseRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow only GitHub's HTTPS release-asset storage redirect."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        source = urllib.parse.urlsplit(request.full_url)
        target = urllib.parse.urlsplit(urllib.parse.urljoin(request.full_url, new_url))
        if (
            source.scheme != "https"
            or source.hostname != "github.com"
            or target.scheme != "https"
            or target.hostname not in ALLOWED_RELEASE_REDIRECT_HOSTS
            or target.port is not None
            or target.username is not None
            or target.password is not None
            or target.fragment
        ):
            raise urllib.error.HTTPError(
                request.full_url,
                code,
                "release asset redirected outside GitHub's HTTPS asset service",
                headers,
                file_pointer,
            )
        return super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )


class RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        raise urllib.error.HTTPError(
            request.full_url, code, "unexpected HTTP redirect", headers, file_pointer
        )


def _read_bounded_response(response, maximum: int) -> bytes:
    length = response.headers.get("Content-Length")
    if length is not None:
        try:
            declared = int(length)
        except ValueError as error:
            raise ValueError("HTTP response has an invalid Content-Length") from error
        if declared < 0 or declared > maximum:
            raise ValueError("HTTP response exceeds its strict size limit")
    content = response.read(maximum + 1)
    if len(content) > maximum:
        raise ValueError("HTTP response exceeds its strict size limit")
    if length is not None and len(content) != declared:
        raise ValueError("HTTP response body does not match Content-Length")
    return content


def fetch_json(url: str) -> object:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.github.com"
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("release metadata must use the canonical GitHub API")
    opener = urllib.request.build_opener(
        RejectRedirectHandler(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "inspace-rke2-e2e-release-verifier/2",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    content = None
    for attempt in range(1, 6):
        try:
            with opener.open(request, timeout=60) as response:
                if response.status != 200:
                    raise ValueError("GitHub release metadata did not return HTTP 200")
                content = _read_bounded_response(response, MAX_METADATA_BYTES)
            break
        except urllib.error.HTTPError as error:
            if error.code not in RETRYABLE_HTTP_STATUSES or attempt == 5:
                raise
        except (
            urllib.error.URLError,
            http.client.RemoteDisconnected,
            TimeoutError,
            ConnectionError,
        ):
            if attempt == 5:
                raise
        time.sleep(attempt * 2)
    if content is None:
        raise RuntimeError("GitHub release metadata retries ended without a response")
    try:
        return json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("GitHub release metadata is not valid JSON") from error


def canonical_release_asset_url(version: str, asset_name: str) -> str:
    return f"{REPOSITORY_URL}/releases/download/v{version}/{asset_name}"


def release_assets(metadata: object, version: str) -> dict[str, dict]:
    tag = "v" + version
    if not isinstance(metadata, dict):
        raise ValueError("GitHub release metadata must be an object")
    if (
        metadata.get("tag_name") != tag
        or metadata.get("draft") is not False
        or metadata.get("prerelease") != ("-" in version)
    ):
        raise ValueError("GitHub release metadata does not match the exact published version")
    assets = metadata.get("assets")
    if not isinstance(assets, list) or any(not isinstance(asset, dict) for asset in assets):
        raise ValueError("GitHub release assets must be an array of objects")
    names = [asset.get("name") for asset in assets]
    if any(not isinstance(name, str) or not name for name in names) or len(names) != len(set(names)):
        raise ValueError("GitHub release asset names must be non-empty and unique")

    required = [
        *(image + ".txt" for image in IMAGE_NAMES),
        *(f"{chart}-{version}.tgz" for chart in CHART_NAMES),
        "SHA256SUMS",
    ]
    if set(names) != set(required):
        raise ValueError("GitHub release must contain exactly the expected artifact set")
    result: dict[str, dict] = {}
    for asset_name in required:
        matching = [asset for asset in assets if asset.get("name") == asset_name]
        if len(matching) != 1:
            raise ValueError(f"GitHub release must contain exactly one {asset_name}")
        asset = matching[0]
        url = asset.get("browser_download_url")
        size = asset.get("size")
        state = asset.get("state")
        asset_id = asset.get("id")
        asset_digest = asset.get("digest")
        content_type = asset.get("content_type")
        maximum = (
            MAX_CHECKSUM_BYTES
            if asset_name == "SHA256SUMS"
            else MAX_CHART_BYTES
            if asset_name.endswith(".tgz")
            else MAX_IMAGE_RECORD_BYTES
        )
        if (
            url != canonical_release_asset_url(version, asset_name)
            or not isinstance(asset_id, int)
            or isinstance(asset_id, bool)
            or asset_id <= 0
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or size > maximum
            or state != "uploaded"
            or not isinstance(asset_digest, str)
            or DIGEST.fullmatch(asset_digest) is None
            or content_type
            != (
                "application/octet-stream"
                if asset_name == "SHA256SUMS"
                else "application/x-gtar"
                if asset_name.endswith(".tgz")
                else "text/plain; charset=utf-8"
            )
        ):
            raise ValueError(f"GitHub release asset {asset_name} metadata is invalid")
        result[asset_name] = {
            "url": url,
            "size": size,
            "digest": asset_digest,
        }
    return result


def release_digest_assets(metadata: object, version: str) -> dict[str, str]:
    """Compatibility helper used by static tests and callers needing image records."""
    assets = release_assets(metadata, version)
    return {image: assets[image + ".txt"]["url"] for image in IMAGE_NAMES}


def fetch_release_asset(asset: dict, maximum: int) -> bytes:
    url = asset["url"]
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("release asset must use its canonical HTTPS GitHub URL")
    opener = urllib.request.build_opener(
        ReleaseRedirectHandler(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    request = urllib.request.Request(
        url, headers={"User-Agent": "inspace-rke2-e2e-release-verifier/2"}
    )
    content = None
    for attempt in range(1, 6):
        try:
            with opener.open(request, timeout=60) as response:
                if response.status != 200:
                    raise ValueError("GitHub release asset did not return HTTP 200")
                final = urllib.parse.urlsplit(response.geturl())
                if (
                    final.scheme != "https"
                    or final.hostname
                    not in ({"github.com"} | ALLOWED_RELEASE_REDIRECT_HOSTS)
                    or final.port is not None
                    or final.username is not None
                    or final.password is not None
                    or final.fragment
                ):
                    raise ValueError(
                        "GitHub release asset resolved outside the approved HTTPS hosts"
                    )
                content = _read_bounded_response(response, maximum)
            break
        except urllib.error.HTTPError as error:
            if error.code not in RETRYABLE_HTTP_STATUSES or attempt == 5:
                raise
        except (
            urllib.error.URLError,
            http.client.RemoteDisconnected,
            TimeoutError,
            ConnectionError,
        ):
            if attempt == 5:
                raise
        time.sleep(attempt * 2)
    if content is None:
        raise RuntimeError("GitHub release asset retries ended without a response")
    if len(content) != asset["size"]:
        raise ValueError("GitHub release asset size differs from release metadata")
    if "sha256:" + hashlib.sha256(content).hexdigest() != asset["digest"]:
        raise ValueError("GitHub release asset body differs from its metadata digest")
    return content


def parse_digest_record(content: str, image: str) -> str:
    lines = content.splitlines()
    prefix = f"ghcr.io/thanet-s/{image}@"
    if len(lines) != 1 or not lines[0].startswith(prefix):
        raise ValueError(f"release digest record for {image} has an unexpected format")
    digest = lines[0][len(prefix):]
    if DIGEST.fullmatch(digest) is None:
        raise ValueError(f"release digest record for {image} has an invalid digest")
    return digest


def parse_chart_checksums(content: bytes, version: str) -> dict[str, str]:
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("SHA256SUMS is not UTF-8") from error
    expected_names = {f"{chart}-{version}.tgz" for chart in CHART_NAMES}
    result: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(
            r"([0-9a-f]{64})  \./([A-Za-z0-9][A-Za-z0-9.-]+\.tgz)", line
        )
        if match is None:
            raise ValueError("SHA256SUMS has an unexpected format")
        digest, name = match.groups()
        if name in result:
            raise ValueError("SHA256SUMS contains a duplicate filename")
        result[name] = digest
    if set(result) != expected_names:
        raise ValueError("SHA256SUMS must contain exactly the two released chart packages")
    return result


def run_json(command: list[str], description: str) -> object:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"{description}: {result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{description} returned malformed JSON") from error


def resolve_tag_digest(image: str, version: str) -> str:
    value = run_json(
        [
            "skopeo",
            "inspect",
            "--retry-times",
            "5",
            f"docker://ghcr.io/thanet-s/{image}:{version}",
        ],
        f"skopeo could not inspect {image}:{version}",
    )
    digest = value.get("Digest") if isinstance(value, dict) else None
    if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
        raise RuntimeError(f"skopeo returned an invalid digest for {image}:{version}")
    return digest


def inspect_raw(reference: str) -> object:
    return run_json(
        [
            "skopeo",
            "inspect",
            "--raw",
            "--retry-times",
            "5",
            "docker://" + reference,
        ],
        f"skopeo could not inspect raw manifest {reference}",
    )


def inspect_config(reference: str) -> object:
    return run_json(
        [
            "skopeo",
            "inspect",
            "--config",
            "--retry-times",
            "5",
            "docker://" + reference,
        ],
        f"skopeo could not inspect image config {reference}",
    )


def linux_amd64_platform_digest(index: object) -> str:
    if not isinstance(index, dict) or index.get("mediaType") not in (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ):
        raise ValueError("release image digest must resolve to an OCI/Docker image index")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or not manifests:
        raise ValueError("release image index must contain manifest descriptors")
    selected = []
    for descriptor in manifests:
        if not isinstance(descriptor, dict):
            raise ValueError("release image index contains a non-object descriptor")
        digest = descriptor.get("digest")
        media_type = descriptor.get("mediaType")
        size = descriptor.get("size")
        platform = descriptor.get("platform")
        if (
            not isinstance(digest, str)
            or DIGEST.fullmatch(digest) is None
            or not isinstance(media_type, str)
            or not media_type
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or not isinstance(platform, dict)
        ):
            raise ValueError("release image index contains a malformed descriptor")
        if platform.get("os") == "linux" and platform.get("architecture") == "amd64":
            selected.append(digest)
    if len(selected) != 1:
        raise ValueError("release image index must contain exactly one linux/amd64 image")
    return selected[0]


def require_platform_identity(
    image: str, digest: str, version: str, revision: str
) -> None:
    reference = f"ghcr.io/thanet-s/{image}@{digest}"
    manifest = inspect_raw(reference)
    if not isinstance(manifest, dict) or manifest.get("mediaType") not in (
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ):
        raise RuntimeError(f"linux/amd64 digest for {image} is not an image manifest")
    config_descriptor = manifest.get("config")
    layers = manifest.get("layers")
    if (
        not isinstance(config_descriptor, dict)
        or DIGEST.fullmatch(str(config_descriptor.get("digest", ""))) is None
        or not isinstance(config_descriptor.get("size"), int)
        or isinstance(config_descriptor.get("size"), bool)
        or config_descriptor["size"] <= 0
        or not isinstance(layers, list)
    ):
        raise RuntimeError(f"linux/amd64 manifest for {image} is incomplete")
    config = inspect_config(reference)
    labels = (
        config.get("config", {}).get("Labels")
        if isinstance(config, dict) and isinstance(config.get("config"), dict)
        else None
    )
    if (
        not isinstance(config, dict)
        or config.get("os") != "linux"
        or config.get("architecture") != "amd64"
        or not isinstance(labels, dict)
        or labels.get("org.opencontainers.image.source") != REPOSITORY_URL
        or labels.get("org.opencontainers.image.version") != version
        or labels.get("org.opencontainers.image.revision") != revision
    ):
        raise RuntimeError(
            f"linux/amd64 image config labels for {image} do not match source/version/revision"
        )


def chart_scalar(metadata: str, key: str) -> str:
    matches = re.findall(
        rf"(?m)^{re.escape(key)}:[ \t]*(?:\"([^\"]*)\"|'([^']*)'|([^#\r\n]*?))[ \t]*$",
        metadata,
    )
    if len(matches) != 1:
        raise ValueError(f"chart metadata must contain exactly one root {key}")
    value = next(part for part in matches[0] if part != "").strip()
    if not value:
        raise ValueError(f"chart metadata root {key} is empty")
    return value


def chart_annotation(metadata: str, key: str) -> str:
    matches = re.findall(
        rf"(?m)^  {re.escape(key)}:[ \t]*(?:\"([^\"]*)\"|'([^']*)'|([^#\r\n]*?))[ \t]*$",
        metadata,
    )
    if len(matches) != 1:
        raise ValueError(f"chart metadata must contain exactly one annotation {key}")
    value = next(part for part in matches[0] if part != "").strip()
    if not value:
        raise ValueError(f"chart metadata annotation {key} is empty")
    return value


def validate_chart_package(
    package: pathlib.Path, chart: str, version: str, revision: str
) -> tuple[str, str, str]:
    result = subprocess.run(
        ["helm", "show", "chart", str(package)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"helm could not inspect released chart {chart}: {result.stderr.strip()}")
    metadata = result.stdout
    app_version = "1.14.0" if chart.endswith("-crds") else version
    if (
        chart_scalar(metadata, "name") != chart
        or chart_scalar(metadata, "version") != version
        or chart_scalar(metadata, "appVersion") != app_version
    ):
        raise ValueError(f"released chart metadata for {chart} does not match the candidate")
    if (
        chart_annotation(metadata, "org.opencontainers.image.source")
        != REPOSITORY_URL
        or chart_annotation(metadata, "org.opencontainers.image.revision")
        != revision
    ):
        raise ValueError(
            f"released chart {chart} lacks its exact OCI source/revision annotations"
        )
    return app_version, REPOSITORY_URL, revision


def verify_oci_chart_bytes(
    release_package: pathlib.Path, chart: str, version: str
) -> None:
    with tempfile.TemporaryDirectory(prefix=f"{chart}-oci-") as temporary:
        pulled = None
        last_error = ""
        for attempt in range(1, 6):
            attempt_directory = pathlib.Path(temporary) / str(attempt)
            attempt_directory.mkdir(mode=0o700)
            result = subprocess.run(
                [
                    "helm",
                    "pull",
                    f"oci://ghcr.io/thanet-s/charts/{chart}",
                    "--version",
                    version,
                    "--destination",
                    str(attempt_directory),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                pulled = attempt_directory
                break
            last_error = result.stderr.strip()
            if attempt < 5:
                time.sleep(attempt * 2)
        if pulled is None:
            raise RuntimeError(
                f"helm could not pull OCI chart {chart}:{version}: {last_error}"
            )
        files = list(pulled.iterdir())
        expected_name = f"{chart}-{version}.tgz"
        if (
            len(files) != 1
            or files[0].name != expected_name
            or not stat.S_ISREG(files[0].lstat().st_mode)
            or files[0].stat().st_size != release_package.stat().st_size
        ):
            raise RuntimeError(f"helm pull returned an unexpected package for {chart}:{version}")
        if not filecmp.cmp(files[0], release_package, shallow=False):
            raise RuntimeError(
                f"OCI chart bytes differ from GitHub release asset for {chart}:{version}"
            )


def _require_directory(path: pathlib.Path, description: str) -> None:
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) not in (
        0o700,
        0o755,
    ):
        raise ValueError(f"{description} must be a non-symlink mode-0700/0755 directory")


def verified_release_images(
    version: str, revision: str, artifact_root: pathlib.Path
) -> dict:
    if VERSION.fullmatch(version) is None:
        raise ValueError("version must be an exact SemVer without a v prefix")
    if REVISION.fullmatch(revision) is None:
        raise ValueError("revision must be the exact lowercase 40-hex peeled tag commit")
    if not artifact_root.exists():
        if not artifact_root.parent.exists():
            _require_directory(artifact_root.parent.parent, "release artifact grandparent")
            artifact_root.parent.mkdir(mode=0o700)
        _require_directory(artifact_root.parent, "release artifact parent")
        artifact_root.mkdir(mode=0o700)
    _require_directory(artifact_root, "release artifact output")
    metadata = fetch_json(
        f"https://api.github.com/repos/{REPOSITORY}/releases/tags/v{version}"
    )
    assets = release_assets(metadata, version)
    checksums_content = fetch_release_asset(
        assets["SHA256SUMS"], MAX_CHECKSUM_BYTES
    )
    checksums = parse_chart_checksums(checksums_content, version)

    charts: dict[str, dict] = {}
    chart_directory = artifact_root / "release-charts"
    chart_directory.mkdir(mode=0o700, exist_ok=True)
    _require_directory(chart_directory, "release chart output")
    for chart in CHART_NAMES:
        filename = f"{chart}-{version}.tgz"
        content = fetch_release_asset(assets[filename], MAX_CHART_BYTES)
        actual = hashlib.sha256(content).hexdigest()
        if actual != checksums[filename]:
            raise RuntimeError(f"GitHub release checksum does not match {filename}")
        package = chart_directory / filename
        atomic_write_bytes(package, content)
        verify_oci_chart_bytes(package, chart, version)
        app_version, source, chart_revision = validate_chart_package(
            package, chart, version, revision
        )
        charts[chart] = {
            "name": chart,
            "version": version,
            "appVersion": app_version,
            "source": source,
            "revision": chart_revision,
            "filename": filename,
            "relativePath": f"release-charts/{filename}",
            "sha256": "sha256:" + actual,
            "releaseURL": assets[filename]["url"],
            "ociReference": f"oci://ghcr.io/thanet-s/charts/{chart}:{version}",
        }

    images: dict[str, dict] = {}
    for image in IMAGE_NAMES:
        record_content = fetch_release_asset(
            assets[image + ".txt"], MAX_IMAGE_RECORD_BYTES
        )
        try:
            recorded = parse_digest_record(record_content.decode("utf-8"), image)
        except UnicodeDecodeError as error:
            raise ValueError(f"release digest record for {image} is not UTF-8") from error
        resolved = resolve_tag_digest(image, version)
        if resolved != recorded:
            raise RuntimeError(
                f"published tag drift for {image}:{version}: "
                f"release records {recorded}, registry resolves {resolved}"
            )
        index = inspect_raw(f"ghcr.io/thanet-s/{image}@{recorded}")
        platform_digest = linux_amd64_platform_digest(index)
        require_platform_identity(image, platform_digest, version, revision)
        images[image] = {
            "releaseDigest": recorded,
            "platformDigest": platform_digest,
            "releaseReference": f"ghcr.io/thanet-s/{image}@{recorded}",
            "platformReference": f"ghcr.io/thanet-s/{image}@{platform_digest}",
        }
    return {
        "schema": SCHEMA,
        "version": version,
        "tag": "v" + version,
        "revision": revision,
        "platform": {"os": "linux", "architecture": "amd64"},
        "images": images,
        "charts": charts,
    }


def validate_release_images_document(
    document: object,
    expected_version: str | None = None,
    expected_revision: str | None = None,
) -> dict:
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "version",
        "tag",
        "revision",
        "platform",
        "images",
        "charts",
    }:
        raise ValueError("release artifact manifest must have its exact schema")
    version = document.get("version")
    revision = document.get("revision")
    if (
        document.get("schema") != SCHEMA
        or not isinstance(version, str)
        or VERSION.fullmatch(version) is None
        or document.get("tag") != "v" + version
        or not isinstance(revision, str)
        or REVISION.fullmatch(revision) is None
        or document.get("platform") != {"os": "linux", "architecture": "amd64"}
        or (expected_version is not None and version != expected_version)
        or (expected_revision is not None and revision != expected_revision)
    ):
        raise ValueError("release artifact manifest identity is invalid")
    images = document.get("images")
    if not isinstance(images, dict) or set(images) != set(IMAGE_NAMES):
        raise ValueError("release artifact manifest must contain exactly the product images")
    for image in IMAGE_NAMES:
        record = images[image]
        if not isinstance(record, dict) or set(record) != {
            "releaseDigest",
            "platformDigest",
            "releaseReference",
            "platformReference",
        }:
            raise ValueError(f"release image manifest record for {image} is invalid")
        release_digest = record["releaseDigest"]
        platform_digest = record["platformDigest"]
        if (
            not isinstance(release_digest, str)
            or DIGEST.fullmatch(release_digest) is None
            or not isinstance(platform_digest, str)
            or DIGEST.fullmatch(platform_digest) is None
            or record["releaseReference"] != f"ghcr.io/thanet-s/{image}@{release_digest}"
            or record["platformReference"] != f"ghcr.io/thanet-s/{image}@{platform_digest}"
        ):
            raise ValueError(f"release image manifest digests for {image} are invalid")
    charts = document.get("charts")
    if not isinstance(charts, dict) or set(charts) != set(CHART_NAMES):
        raise ValueError("release artifact manifest must contain exactly the two Helm charts")
    for chart in CHART_NAMES:
        record = charts[chart]
        filename = f"{chart}-{version}.tgz"
        app_version = "1.14.0" if chart.endswith("-crds") else version
        if (
            not isinstance(record, dict)
            or set(record)
            != {
                "name",
                "version",
                "appVersion",
                "source",
                "revision",
                "filename",
                "relativePath",
                "sha256",
                "releaseURL",
                "ociReference",
            }
            or record["name"] != chart
            or record["version"] != version
            or record["appVersion"] != app_version
            or record["source"] != REPOSITORY_URL
            or record["revision"] != revision
            or record["filename"] != filename
            or record["relativePath"] != f"release-charts/{filename}"
            or not isinstance(record["sha256"], str)
            or DIGEST.fullmatch(record["sha256"]) is None
            or record["releaseURL"] != canonical_release_asset_url(version, filename)
            or record["ociReference"]
            != f"oci://ghcr.io/thanet-s/charts/{chart}:{version}"
        ):
            raise ValueError(f"release chart manifest record for {chart} is invalid")
    return document


def _read_strict_file(path: pathlib.Path, maximum: int) -> bytes:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size <= 0
        or metadata.st_size > maximum
    ):
        raise ValueError(f"persisted release artifact must be a bounded mode-0600 file: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        current = os.fstat(descriptor)
        if current.st_ino != metadata.st_ino or current.st_dev != metadata.st_dev:
            raise ValueError(f"persisted release artifact changed while opening: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(maximum + 1)
    finally:
        os.close(descriptor)
    if len(content) != metadata.st_size:
        raise ValueError(f"persisted release artifact changed while reading: {path}")
    return content


def load_document(root: pathlib.Path) -> dict:
    _require_directory(root, "persisted E2E run")
    content = _read_strict_file(root / "release-images.json", MAX_METADATA_BYTES)
    try:
        document = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("persisted release artifact manifest is invalid JSON") from error
    result = validate_release_images_document(document)
    _require_directory(root / "release-charts", "persisted release chart directory")
    for chart in CHART_NAMES:
        record = result["charts"][chart]
        package = root / record["relativePath"]
        content = _read_strict_file(package, MAX_CHART_BYTES)
        if "sha256:" + hashlib.sha256(content).hexdigest() != record["sha256"]:
            raise ValueError(f"persisted release chart checksum changed for {chart}")
        validate_chart_package(
            package, chart, result["version"], result["revision"]
        )
    return result


def _read_run_id(path: pathlib.Path) -> str:
    content = _read_strict_file(path, 128)
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("last-run-id is not UTF-8") from error
    if not text.endswith("\n") or text.count("\n") != 1:
        raise ValueError("last-run-id must contain exactly one newline-terminated run ID")
    return text[:-1]


def load_persisted_release_images(state_root: pathlib.Path, run_id: str | None) -> dict:
    _require_directory(state_root, "persisted E2E state root")
    if run_id is None or run_id == "":
        run_id = _read_run_id(state_root / "last-run-id")
    if RUN_ID.fullmatch(run_id) is None:
        raise ValueError("persisted release lookup run ID is invalid")
    run_root = state_root / run_id
    _require_directory(run_root, "persisted E2E run")
    result = load_document(run_root)
    state_path = run_root / "state.json"
    if not state_path.exists():
        if state_path.is_symlink():
            raise ValueError("persisted ownership journal must not be a symlink")
        marker = _read_strict_file(run_root / "mutations-not-started", 128)
        mutation_marker = run_root / "mutations-may-exist"
        if (
            marker != b"mutations-not-started\n"
            or mutation_marker.exists()
            or mutation_marker.is_symlink()
        ):
            raise ValueError(
                "journal-free persisted run lacks proof that remote mutations never started"
            )
        return result
    state_content = _read_strict_file(state_path, MAX_METADATA_BYTES)
    try:
        state = json.loads(state_content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("persisted ownership journal is invalid JSON") from error
    if not isinstance(state, dict) or state.get("runID") != run_id:
        raise ValueError("persisted ownership journal does not bind its direct-child run ID")
    return result


def copy_artifacts_to_state(source_root: pathlib.Path, state_root: pathlib.Path, document: dict) -> None:
    if state_root.exists():
        _require_directory(state_root, "E2E run state")
    else:
        state_root.mkdir(mode=0o700)
    chart_directory = state_root / "release-charts"
    chart_directory.mkdir(mode=0o700, exist_ok=True)
    _require_directory(chart_directory, "persisted release chart directory")
    for chart in CHART_NAMES:
        relative = pathlib.Path(document["charts"][chart]["relativePath"])
        atomic_write_bytes(
            state_root / relative,
            _read_strict_file(source_root / relative, MAX_CHART_BYTES),
        )
    atomic_write_json(state_root / "release-images.json", document)


def require_environment_binding(result: dict, prefix: str) -> None:
    if os.environ.get(prefix + "VERSION") != result["version"]:
        raise ValueError(f"{prefix}VERSION does not match the verified release manifest")
    if os.environ.get(prefix + "REVISION") != result["revision"]:
        raise ValueError(f"{prefix}REVISION does not match the verified release manifest")
    for image in IMAGE_NAMES:
        image_prefix = ENV_PREFIXES[image]
        for field, suffix in (
            ("releaseDigest", "RELEASE_DIGEST"),
            ("platformDigest", "PLATFORM_DIGEST"),
        ):
            name = prefix + image_prefix.removeprefix("INSPACE_E2E_") + "_" + suffix
            if os.environ.get(name) != result["images"][image][field]:
                raise ValueError(f"{name} does not match the verified release manifest")
    for chart in CHART_NAMES:
        name = (
            prefix
            + CHART_ENV_PREFIXES[chart].removeprefix("INSPACE_E2E_")
            + "_DIGEST"
        )
        if os.environ.get(name) != result["charts"][chart]["sha256"]:
            raise ValueError(f"{name} does not match the verified release manifest")


def print_environment(result: dict) -> None:
    print(f"INSPACE_E2E_RELEASE_VERSION={result['version']}")
    print(f"INSPACE_E2E_RELEASE_REVISION={result['revision']}")
    for image in IMAGE_NAMES:
        prefix = ENV_PREFIXES[image]
        print(f"{prefix}_RELEASE_DIGEST={result['images'][image]['releaseDigest']}")
        print(f"{prefix}_PLATFORM_DIGEST={result['images'][image]['platformDigest']}")
    for chart in CHART_NAMES:
        prefix = CHART_ENV_PREFIXES[chart]
        print(f"{prefix}_DIGEST={result['charts'][chart]['sha256']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--version")
    source.add_argument("--persisted-state-root", type=pathlib.Path)
    source.add_argument("--artifact-root", type=pathlib.Path)
    parser.add_argument("--revision")
    parser.add_argument("--artifact-dir", type=pathlib.Path)
    parser.add_argument("--run-id")
    parser.add_argument("--copy-to-state", type=pathlib.Path)
    parser.add_argument("--output", required=True)
    parser.add_argument("--format", choices=("json", "env"), default="json")
    parser.add_argument(
        "--expect-environment-prefix",
        choices=("INSPACE_E2E_", "INSPACE_E2E_BUILT_"),
    )
    args = parser.parse_args()
    if args.version is not None:
        if args.run_id is not None or args.revision is None or args.artifact_dir is None:
            parser.error("--version requires --revision and --artifact-dir, but not --run-id")
        result = validate_release_images_document(
            verified_release_images(args.version, args.revision, args.artifact_dir),
            args.version,
            args.revision,
        )
        source_root = args.artifact_dir
    elif args.persisted_state_root is not None:
        if args.revision is not None or args.artifact_dir is not None:
            parser.error("persisted lookup does not accept --revision or --artifact-dir")
        result = load_persisted_release_images(args.persisted_state_root, args.run_id)
        selected_run = args.run_id
        if not selected_run:
            selected_run = _read_run_id(args.persisted_state_root / "last-run-id")
        source_root = args.persisted_state_root / selected_run
    else:
        if (
            args.run_id is not None
            or args.revision is not None
            or args.artifact_dir is not None
        ):
            parser.error("artifact-root lookup does not accept run/version arguments")
        result = load_document(args.artifact_root)
        source_root = args.artifact_root
    if args.expect_environment_prefix is not None:
        require_environment_binding(result, args.expect_environment_prefix)
    if args.copy_to_state is not None:
        copy_artifacts_to_state(source_root, args.copy_to_state, result)
    atomic_write_json(pathlib.Path(args.output), result)
    if args.format == "json":
        print(json.dumps(result, sort_keys=True))
    else:
        print_environment(result)


if __name__ == "__main__":
    main()
