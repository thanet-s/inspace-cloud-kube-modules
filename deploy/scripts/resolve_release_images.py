#!/usr/bin/env python3
"""Resolve one release's controller images to immutable digests.

Usage: resolve_release_images.py <version>

The release workflow records each merged image-index digest as an asset of the
immutable GitHub release. This reads those records anonymously, checks each
body against the digest GitHub reports for the asset, then reads the index,
its linux/amd64 manifest, and that manifest's config from ghcr.io by digest,
checking every body's sha256 and that the config labels name this repository
and exact version. A mutable tag is never consulted.

Prints JSON: {"version": ..., "images": {<image>: {"releaseDigest",
"platformDigest", "releaseReference", "platformReference"}}}.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


REPOSITORY = "thanet-s/inspace-cloud-kube-modules"
REPOSITORY_URL = f"https://github.com/{REPOSITORY}"
REGISTRY = "ghcr.io"
OWNER = "thanet-s"
IMAGE_NAMES = (
    "inspace-cloud-controller-manager",
    "inspace-csi-driver",
    "karpenter-provider-inspace",
)
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
INDEX_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)
MANIFEST_TYPES = (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_RECORD_BYTES = 4096
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_CONFIG_BYTES = 4 * 1024 * 1024
RELEASE_ASSET_HOSTS = {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
REGISTRY_BLOB_HOSTS = {"pkg-containers.githubusercontent.com"}
RETRYABLE_HTTP_STATUSES = {408, 429, 500, 502, 503, 504}
USER_AGENT = "inspace-deploy-release-image-resolver/1"


class ResolutionError(Exception):
    pass


def _https_url(url: str, hosts: set[str], allow_query: bool = False) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in hosts
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (parsed.query and not allow_query)
    ):
        raise ResolutionError(f"refusing a URL outside the approved HTTPS hosts: {url}")
    return parsed


class _AllowListRedirect(urllib.request.HTTPRedirectHandler):
    """Follow one storage redirect to an allow-listed host, without credentials."""

    def __init__(self, hosts: set[str]) -> None:
        super().__init__()
        self.hosts = hosts

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        target = urllib.parse.urljoin(request.full_url, new_url)
        try:
            _https_url(target, self.hosts, allow_query=True)
        except ResolutionError as error:
            raise urllib.error.HTTPError(
                request.full_url, code, str(error), headers, file_pointer
            ) from error
        redirected = super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )
        if redirected is not None:
            redirected.remove_header("Authorization")
        return redirected


def _read_bounded(response, maximum: int) -> bytes:
    length = response.headers.get("Content-Length")
    declared = None
    if length is not None:
        try:
            declared = int(length)
        except ValueError as error:
            raise ResolutionError("HTTP response has an invalid Content-Length") from error
        if declared < 0 or declared > maximum:
            raise ResolutionError("HTTP response exceeds its size limit")
    content = response.read(maximum + 1)
    if len(content) > maximum:
        raise ResolutionError("HTTP response exceeds its size limit")
    if declared is not None and len(content) != declared:
        raise ResolutionError("HTTP response body does not match Content-Length")
    return content


def http_get(
    url: str,
    hosts: set[str],
    maximum: int,
    headers: dict[str, str] | None = None,
    redirect_hosts: set[str] | None = None,
    allow_query: bool = False,
) -> bytes:
    _https_url(url, hosts, allow_query=allow_query)
    handlers: list[urllib.request.BaseHandler] = [
        urllib.request.HTTPSHandler(context=ssl.create_default_context())
    ]
    handlers.append(_AllowListRedirect(redirect_hosts or set()))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    for attempt in range(1, 6):
        try:
            with opener.open(request, timeout=60) as response:
                if response.status != 200:
                    raise ResolutionError(f"{url} did not return HTTP 200")
                final = response.geturl()
                _https_url(final, hosts | (redirect_hosts or set()), allow_query=True)
                return _read_bounded(response, maximum)
        except urllib.error.HTTPError as error:
            if error.code not in RETRYABLE_HTTP_STATUSES or attempt == 5:
                raise ResolutionError(f"{url} returned HTTP {error.code}") from error
        except (urllib.error.URLError, http.client.HTTPException, TimeoutError, ConnectionError) as error:
            if attempt == 5:
                raise ResolutionError(f"{url} is unreachable: {error}") from error
        time.sleep(attempt * 2)
    raise ResolutionError(f"{url} retries ended without a response")


def sha256_digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def release_record_assets(metadata: object, version: str) -> dict[str, dict]:
    if not isinstance(metadata, dict):
        raise ResolutionError("GitHub release metadata must be an object")
    if (
        metadata.get("tag_name") != "v" + version
        or metadata.get("draft") is not False
        or metadata.get("prerelease") is not ("-" in version)
        or metadata.get("immutable") is not True
    ):
        raise ResolutionError(
            f"v{version} is not a published immutable GitHub release of {REPOSITORY}"
        )
    assets = metadata.get("assets")
    if not isinstance(assets, list) or any(not isinstance(asset, dict) for asset in assets):
        raise ResolutionError("GitHub release assets must be an array of objects")
    result: dict[str, dict] = {}
    for image in IMAGE_NAMES:
        name = image + ".txt"
        matching = [asset for asset in assets if asset.get("name") == name]
        if len(matching) != 1:
            raise ResolutionError(f"v{version} must carry exactly one {name} image-digest record")
        asset = matching[0]
        size = asset.get("size")
        digest = asset.get("digest")
        if (
            asset.get("browser_download_url")
            != f"{REPOSITORY_URL}/releases/download/v{version}/{name}"
            or asset.get("state") != "uploaded"
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 < size <= MAX_RECORD_BYTES
            or not isinstance(digest, str)
            or DIGEST.fullmatch(digest) is None
        ):
            raise ResolutionError(f"GitHub release asset {name} metadata is invalid")
        result[image] = {"url": asset["browser_download_url"], "size": size, "digest": digest}
    return result


def parse_digest_record(content: bytes, image: str) -> str:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ResolutionError(f"image-digest record for {image} is not UTF-8") from error
    prefix = f"{REGISTRY}/{OWNER}/{image}@"
    if text.count("\n") != 1 or not text.endswith("\n") or not text.startswith(prefix):
        raise ResolutionError(f"image-digest record for {image} has an unexpected format")
    digest = text[len(prefix) : -1]
    if DIGEST.fullmatch(digest) is None:
        raise ResolutionError(f"image-digest record for {image} has an invalid digest")
    return digest


def _json_document(content: bytes, digest: str, description: str) -> dict:
    if sha256_digest(content) != digest:
        raise ResolutionError(f"{description} body does not match {digest}")
    try:
        document = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ResolutionError(f"{description} is not valid JSON") from error
    if not isinstance(document, dict):
        raise ResolutionError(f"{description} must be a JSON object")
    return document


def linux_amd64_manifest(index_content: bytes, index_digest: str, image: str) -> str:
    index = _json_document(index_content, index_digest, f"{image} image index")
    if index.get("mediaType") not in INDEX_TYPES or not isinstance(index.get("manifests"), list):
        raise ResolutionError(f"{image}@{index_digest} is not a multi-platform image index")
    selected = []
    for descriptor in index["manifests"]:
        if not isinstance(descriptor, dict):
            raise ResolutionError(f"{image} image index has a malformed descriptor")
        platform = descriptor.get("platform")
        if (
            isinstance(platform, dict)
            and platform.get("os") == "linux"
            and platform.get("architecture") == "amd64"
        ):
            selected.append(descriptor)
    if len(selected) != 1:
        raise ResolutionError(f"{image} image index must hold exactly one linux/amd64 image")
    descriptor = selected[0]
    digest = descriptor.get("digest")
    if (
        descriptor.get("mediaType") not in MANIFEST_TYPES
        or not isinstance(digest, str)
        or DIGEST.fullmatch(digest) is None
    ):
        raise ResolutionError(f"{image} linux/amd64 descriptor is malformed")
    return digest


def manifest_config(manifest_content: bytes, manifest_digest: str, image: str) -> str:
    manifest = _json_document(manifest_content, manifest_digest, f"{image} linux/amd64 manifest")
    config = manifest.get("config")
    if (
        manifest.get("mediaType") not in MANIFEST_TYPES
        or not isinstance(config, dict)
        or not isinstance(config.get("digest"), str)
        or DIGEST.fullmatch(config["digest"]) is None
    ):
        raise ResolutionError(f"{image} linux/amd64 manifest is incomplete")
    return config["digest"]


def require_config_identity(config_content: bytes, config_digest: str, image: str, version: str) -> None:
    config = _json_document(config_content, config_digest, f"{image} image config")
    labels = config.get("config", {}).get("Labels") if isinstance(config.get("config"), dict) else None
    if (
        config.get("os") != "linux"
        or config.get("architecture") != "amd64"
        or not isinstance(labels, dict)
        or labels.get("org.opencontainers.image.source") != REPOSITORY_URL
        or labels.get("org.opencontainers.image.version") != version
    ):
        raise ResolutionError(f"{image} image config does not identify {REPOSITORY_URL} {version}")


class Network:
    """Anonymous, allow-listed reads from GitHub releases and ghcr.io."""

    def __init__(self) -> None:
        self.tokens: dict[str, str] = {}

    def release_metadata(self, version: str) -> object:
        content = http_get(
            f"https://api.github.com/repos/{REPOSITORY}/releases/tags/v{version}",
            {"api.github.com"},
            MAX_METADATA_BYTES,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            return json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ResolutionError("GitHub release metadata is not valid JSON") from error

    def release_asset(self, asset: dict) -> bytes:
        content = http_get(
            asset["url"], {"github.com"}, MAX_RECORD_BYTES, redirect_hosts=RELEASE_ASSET_HOSTS
        )
        if len(content) != asset["size"] or sha256_digest(content) != asset["digest"]:
            raise ResolutionError("GitHub release asset body differs from its release metadata")
        return content

    def _token(self, image: str) -> str:
        if image not in self.tokens:
            scope = urllib.parse.quote(f"repository:{OWNER}/{image}:pull", safe=":/")
            content = http_get(
                f"https://{REGISTRY}/token?scope={scope}&service={REGISTRY}",
                {REGISTRY},
                MAX_METADATA_BYTES,
                allow_query=True,
            )
            try:
                token = json.loads(content).get("token")
            except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as error:
                raise ResolutionError("ghcr.io returned a malformed anonymous token") from error
            if not isinstance(token, str) or not token:
                raise ResolutionError("ghcr.io returned an empty anonymous token")
            self.tokens[image] = token
        return self.tokens[image]

    def manifest(self, image: str, digest: str) -> bytes:
        return http_get(
            f"https://{REGISTRY}/v2/{OWNER}/{image}/manifests/{digest}",
            {REGISTRY},
            MAX_MANIFEST_BYTES,
            headers={
                "Accept": ", ".join(INDEX_TYPES + MANIFEST_TYPES),
                "Authorization": "Bearer " + self._token(image),
            },
        )

    def blob(self, image: str, digest: str) -> bytes:
        return http_get(
            f"https://{REGISTRY}/v2/{OWNER}/{image}/blobs/{digest}",
            {REGISTRY},
            MAX_CONFIG_BYTES,
            headers={"Authorization": "Bearer " + self._token(image)},
            redirect_hosts=REGISTRY_BLOB_HOSTS,
        )


def resolve(version: str, network) -> dict:
    if VERSION.fullmatch(version) is None:
        raise ResolutionError("version must be an exact SemVer without a v prefix")
    assets = release_record_assets(network.release_metadata(version), version)
    images: dict[str, dict] = {}
    for image in IMAGE_NAMES:
        release_digest = parse_digest_record(network.release_asset(assets[image]), image)
        platform_digest = linux_amd64_manifest(
            network.manifest(image, release_digest), release_digest, image
        )
        config_digest = manifest_config(
            network.manifest(image, platform_digest), platform_digest, image
        )
        require_config_identity(network.blob(image, config_digest), config_digest, image, version)
        repository = f"{REGISTRY}/{OWNER}/{image}"
        images[image] = {
            "releaseDigest": release_digest,
            "platformDigest": platform_digest,
            "releaseReference": f"{repository}@{release_digest}",
            "platformReference": f"{repository}@{platform_digest}",
        }
    return {"version": version, "images": images}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: resolve_release_images.py <version>", file=sys.stderr)
        return 2
    try:
        document = resolve(argv[1], Network())
    except ResolutionError as error:
        print(f"release image resolution failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
