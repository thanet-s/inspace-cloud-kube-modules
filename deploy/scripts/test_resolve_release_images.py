#!/usr/bin/env python3
"""Offline tests for resolve_release_images.py's digest-binding checks."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest

from resolve_release_images import (
    IMAGE_NAMES,
    REPOSITORY_URL,
    ResolutionError,
    resolve,
)


VERSION = "1.2.3-rc.1"


def digest_of(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def encoded(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True).encode("utf-8")


class FakeRegistry:
    """One published release with content-addressed ghcr.io objects."""

    def __init__(self, version: str = VERSION) -> None:
        self.version = version
        self.records: dict[str, bytes] = {}
        self.objects: dict[str, dict[str, bytes]] = {}
        self.expected: dict[str, tuple[str, str]] = {}
        for image in IMAGE_NAMES:
            config = encoded(
                {
                    "os": "linux",
                    "architecture": "amd64",
                    "config": {
                        "Labels": {
                            "org.opencontainers.image.source": REPOSITORY_URL,
                            "org.opencontainers.image.version": version,
                        }
                    },
                }
            )
            manifest = encoded(
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "config": {"digest": digest_of(config), "size": len(config)},
                    "layers": [],
                }
            )
            attestation = encoded({"mediaType": "application/vnd.oci.image.manifest.v1+json"})
            index = encoded(
                {
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "manifests": [
                        {
                            "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "digest": digest_of(manifest),
                            "size": len(manifest),
                            "platform": {"os": "linux", "architecture": "amd64"},
                        },
                        {
                            "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "digest": digest_of(attestation),
                            "size": len(attestation),
                            "platform": {"os": "unknown", "architecture": "unknown"},
                        },
                    ],
                }
            )
            self.objects[image] = {
                digest_of(index): index,
                digest_of(manifest): manifest,
                digest_of(config): config,
            }
            self.records[image] = f"ghcr.io/thanet-s/{image}@{digest_of(index)}\n".encode()
            self.expected[image] = (digest_of(index), digest_of(manifest))
        self.metadata = {
            "tag_name": "v" + version,
            "draft": False,
            "prerelease": "-" in version,
            "immutable": True,
            "assets": [self.asset(image) for image in IMAGE_NAMES],
        }

    def asset(self, image: str) -> dict:
        record = self.records[image]
        return {
            "name": image + ".txt",
            "browser_download_url": f"{REPOSITORY_URL}/releases/download/v{self.version}/{image}.txt",
            "state": "uploaded",
            "size": len(record),
            "digest": digest_of(record),
        }

    def release_metadata(self, version: str) -> object:
        return copy.deepcopy(self.metadata)

    def release_asset(self, asset: dict) -> bytes:
        image = asset["url"].rsplit("/", 1)[-1][: -len(".txt")]
        content = self.records[image]
        if len(content) != asset["size"] or digest_of(content) != asset["digest"]:
            raise ResolutionError("GitHub release asset body differs from its release metadata")
        return content

    def manifest(self, image: str, digest: str) -> bytes:
        return self.objects[image][digest]

    def blob(self, image: str, digest: str) -> bytes:
        return self.objects[image][digest]


class ResolveReleaseImagesTest(unittest.TestCase):
    def test_resolves_release_index_and_linux_amd64_digests(self) -> None:
        registry = FakeRegistry()
        document = resolve(VERSION, registry)
        self.assertEqual(document["version"], VERSION)
        self.assertEqual(set(document["images"]), set(IMAGE_NAMES))
        for image, (release_digest, platform_digest) in registry.expected.items():
            record = document["images"][image]
            self.assertEqual(record["releaseDigest"], release_digest)
            self.assertEqual(record["platformDigest"], platform_digest)
            self.assertEqual(record["releaseReference"], f"ghcr.io/thanet-s/{image}@{release_digest}")
            self.assertEqual(record["platformReference"], f"ghcr.io/thanet-s/{image}@{platform_digest}")

    def test_rejects_non_exact_versions(self) -> None:
        for version in ("v1.2.3", "1.2", "1.2.3+build", "latest", ""):
            with self.subTest(version=version), self.assertRaises(ResolutionError):
                resolve(version, FakeRegistry())

    def test_rejects_draft_mutable_mismatched_or_mislabelled_releases(self) -> None:
        for field, value in (
            ("draft", True),
            ("immutable", False),
            ("tag_name", "v1.2.4"),
            ("prerelease", False),
        ):
            with self.subTest(field=field):
                registry = FakeRegistry()
                registry.metadata[field] = value
                with self.assertRaises(ResolutionError):
                    resolve(VERSION, registry)
        registry = FakeRegistry()
        del registry.metadata["immutable"]
        with self.assertRaises(ResolutionError):
            resolve(VERSION, registry)

    def test_rejects_missing_duplicate_or_non_canonical_record_assets(self) -> None:
        registry = FakeRegistry()
        registry.metadata["assets"].pop(1)
        with self.assertRaises(ResolutionError):
            resolve(VERSION, registry)
        registry = FakeRegistry()
        registry.metadata["assets"].append(registry.asset(IMAGE_NAMES[0]))
        with self.assertRaises(ResolutionError):
            resolve(VERSION, registry)
        registry = FakeRegistry()
        registry.metadata["assets"][0]["browser_download_url"] = "https://example.com/record.txt"
        with self.assertRaises(ResolutionError):
            resolve(VERSION, registry)

    def test_rejects_record_bodies_that_differ_from_release_metadata(self) -> None:
        registry = FakeRegistry()
        image = IMAGE_NAMES[1]
        registry.records[image] = f"ghcr.io/thanet-s/{image}@sha256:{'0' * 64}\n".encode()
        with self.assertRaises(ResolutionError):
            resolve(VERSION, registry)

    def test_rejects_tag_or_foreign_repository_records(self) -> None:
        for content in (
            f"ghcr.io/thanet-s/inspace-csi-driver:{VERSION}\n",
            f"ghcr.io/attacker/inspace-csi-driver@sha256:{'1' * 64}\n",
            f"ghcr.io/thanet-s/inspace-csi-driver@sha256:{'1' * 64}\nextra\n",
            f"ghcr.io/thanet-s/inspace-csi-driver@sha256:{'1' * 64}",
        ):
            with self.subTest(content=content):
                registry = FakeRegistry()
                registry.records["inspace-csi-driver"] = content.encode()
                registry.metadata["assets"] = [registry.asset(image) for image in IMAGE_NAMES]
                with self.assertRaises(ResolutionError):
                    resolve(VERSION, registry)

    def test_rejects_registry_bodies_that_do_not_hash_to_the_requested_digest(self) -> None:
        for position in range(3):
            with self.subTest(position=position):
                registry = FakeRegistry()
                image = IMAGE_NAMES[0]
                key = list(registry.objects[image])[position]
                registry.objects[image][key] = registry.objects[image][key] + b" "
                with self.assertRaises(ResolutionError):
                    resolve(VERSION, registry)

    def test_rejects_an_index_without_exactly_one_linux_amd64_image(self) -> None:
        registry = FakeRegistry()
        image = IMAGE_NAMES[2]
        release_digest, _platform_digest = registry.expected[image]
        index = json.loads(registry.objects[image][release_digest])
        index["manifests"].append(copy.deepcopy(index["manifests"][0]))
        replacement = encoded(index)
        del registry.objects[image][release_digest]
        registry.objects[image][digest_of(replacement)] = replacement
        registry.records[image] = f"ghcr.io/thanet-s/{image}@{digest_of(replacement)}\n".encode()
        registry.metadata["assets"] = [registry.asset(name) for name in IMAGE_NAMES]
        with self.assertRaises(ResolutionError):
            resolve(VERSION, registry)

    def test_rejects_an_image_labelled_for_another_version(self) -> None:
        registry = FakeRegistry()
        other = FakeRegistry("1.2.2")
        image = IMAGE_NAMES[0]
        registry.objects[image] = other.objects[image]
        registry.records[image] = other.records[image]
        registry.metadata["assets"] = [registry.asset(name) for name in IMAGE_NAMES]
        with self.assertRaises(ResolutionError):
            resolve(VERSION, registry)


if __name__ == "__main__":
    unittest.main()
