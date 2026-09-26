#!/usr/bin/env python3
"""Black-box checks for pinning the release chart's controller images by digest."""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pin-release-chart-images.py"
VALUES = ROOT / "charts" / "inspace-cloud-kube-modules" / "values.yaml"
IMAGES = {
    "inspace-cloud-controller-manager": "sha256:" + "a" * 64,
    "inspace-csi-driver": "sha256:" + "b" * 64,
    "karpenter-provider-inspace": "sha256:" + "c" * 64,
}
VERSION = "1.2.3-rc.4"


class PinReleaseChartImagesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = pathlib.Path(tempfile.mkdtemp(prefix="pin-release-chart-"))
        self.values = self.directory / "values.yaml"
        # Normalize a Windows checkout so the byte-level assertions match CI.
        self.values.write_bytes(VALUES.read_bytes().replace(b"\r\n", b"\n"))
        self.original = self.values.read_text(encoding="utf-8")
        self.records = self.directory / "image-digests"
        self.records.mkdir()
        for image, digest in IMAGES.items():
            self.write_record(image, f"ghcr.io/thanet-s/{image}@{digest}\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.directory)

    def write_record(self, image: str, content: str) -> None:
        (self.records / f"{image}.txt").write_bytes(content.encode("utf-8"))

    def run_pin(self, version: str = VERSION) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.values), str(self.records), version],
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_rejected(self, message: str, version: str = VERSION) -> None:
        result = self.run_pin(version)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)
        self.assertEqual(self.values.read_text(encoding="utf-8"), self.original)

    def test_pins_exact_tag_and_index_digest_for_every_controller(self) -> None:
        result = self.run_pin()
        self.assertEqual(result.returncode, 0, result.stderr)
        pinned = self.values.read_text(encoding="utf-8")
        for image, digest in IMAGES.items():
            block = re.search(
                rf"(?m)^    repository: ghcr\.io/thanet-s/{image}\n(?:    #[^\n]*\n)*"
                rf'    tag: "{re.escape(VERSION)}"\n    digest: "{digest}"\n',
                pinned,
            )
            self.assertIsNotNone(block, image)
        self.assertEqual(len(re.findall(r'(?m)^    tag: ""$', pinned)), 0)
        self.assertEqual(len(re.findall(r'(?m)^    digest: ""$', pinned)), 0)
        # Nothing but the six release-managed scalars may change.
        changed = [
            (before, after)
            for before, after in zip(self.original.splitlines(), pinned.splitlines())
            if before != after
        ]
        self.assertEqual(len(self.original.splitlines()), len(pinned.splitlines()))
        self.assertEqual(len(changed), 6)
        for before, _after in changed:
            self.assertIn(before, ('    tag: ""', '    digest: ""'))

    def test_rejects_a_record_for_another_repository(self) -> None:
        self.write_record(
            "inspace-csi-driver",
            "ghcr.io/someone-else/inspace-csi-driver@" + IMAGES["inspace-csi-driver"] + "\n",
        )
        self.assert_rejected("inspace-csi-driver")

    def test_rejects_a_tag_instead_of_a_digest(self) -> None:
        self.write_record(
            "karpenter-provider-inspace",
            f"ghcr.io/thanet-s/karpenter-provider-inspace:{VERSION}\n",
        )
        self.assert_rejected("karpenter-provider-inspace")

    def test_rejects_a_multi_line_or_malformed_digest_record(self) -> None:
        record = "ghcr.io/thanet-s/inspace-cloud-controller-manager@" + IMAGES["inspace-cloud-controller-manager"]
        for content in (record + "\n" + record + "\n", record.upper() + "\n", record[:-1] + "\n", ""):
            with self.subTest(content=content):
                self.write_record("inspace-cloud-controller-manager", content)
                self.assert_rejected("inspace-cloud-controller-manager")

    def test_rejects_missing_or_unexpected_records(self) -> None:
        (self.records / "inspace-csi-driver.txt").unlink()
        self.assert_rejected("exactly the three")
        self.write_record("inspace-csi-driver", f"ghcr.io/thanet-s/inspace-csi-driver@{IMAGES['inspace-csi-driver']}\n")
        self.write_record("unexpected", "ghcr.io/thanet-s/unexpected@" + "sha256:" + "d" * 64 + "\n")
        self.assert_rejected("exactly the three")

    def test_rejects_values_that_are_not_release_managed_placeholders(self) -> None:
        self.values.write_bytes(
            self.original.replace(
                '    digest: ""\n', '    digest: "sha256:' + "e" * 64 + '"\n', 1
            ).encode("utf-8")
        )
        self.original = self.values.read_text(encoding="utf-8")
        self.assert_rejected("inspace-cloud-controller-manager")

    def test_rejects_non_semver_versions(self) -> None:
        for version in ("v1.2.3", "1.2", "1.2.3+build", "", "1.2.3\n"):
            with self.subTest(version=version):
                self.assert_rejected("version", version)


if __name__ == "__main__":
    unittest.main()
