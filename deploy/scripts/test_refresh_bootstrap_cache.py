#!/usr/bin/env python3
"""Behavioural tests for deploy/templates/refresh-bootstrap-cache.sh.

The script runs as root on the bastion. Here it runs against a temporary
root with stub skopeo, curl, docker, findmnt, df, and flock commands that
model the private registry, the upstream registries, and GitHub releases.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = ROOT / "deploy" / "templates" / "refresh-bootstrap-cache.sh"
FRONT = "cache.unit.inspace.internal:8443"
RKE2_VERSION = "v1.36.5+rke2r1"
RKE2_ARCHIVE = b"rke2 release archive bytes\n"
RKE2_SHA = hashlib.sha256(RKE2_ARCHIVE).hexdigest()
RKE2_BASE = "https://github.com/rancher/rke2/releases/download/v1.36.5%2Brke2r1"

STUB_COMMON = r'''#!/usr/bin/env python3
import json, os, sys
STATE = os.environ["STUB_STATE"]
def load():
    with open(STATE, encoding="utf-8") as handle:
        return json.load(handle)
def save(state):
    with open(STATE, "w", encoding="utf-8") as handle:
        json.dump(state, handle)
def log(state, entry):
    state["log"].append(entry)
'''

STUBS = {
    "skopeo": STUB_COMMON + r'''
state = load()
args = sys.argv[1:]
if args[0] == "inspect":
    reference = args[-1]
    log(state, "inspect " + reference)
    save(state)
    if reference not in state["upstream"]:
        sys.stderr.write("manifest unknown\n")
        sys.exit(1)
    sys.stdout.write(state["upstream"][reference])
    sys.exit(0)
if args[0] == "copy":
    source, destination = args[-2], args[-1]
    log(state, "copy " + source + " " + destination)
    assert "--preserve-digests" in args and "--dest-tls-verify=false" in args, args
    if state["readonly"]:
        save(state)
        sys.stderr.write("405 method not allowed\n")
        sys.exit(1)
    target = destination.split("127.0.0.1:5000/", 1)[1]
    state["registry"][target] = state["copy_digest"].get(target, source.rsplit("@", 1)[1])
    save(state)
    sys.exit(0)
sys.exit(2)
''',
    "curl": STUB_COMMON + r'''
state = load()
args = sys.argv[1:]
url = args[-1]
def option(name):
    return args[args.index(name) + 1] if name in args else None
dump, output, write_out, method = option("--dump-header"), option("--output"), option("--write-out"), option("--request")
head = "--head" in args
log(state, " ".join(["curl"] + (["HEAD"] if head else []) + ([method] if method else []) + [url]))
save(state)
def finish(status, headers=""):
    if dump:
        with open(dump, "w", encoding="utf-8") as handle:
            handle.write(headers)
    if write_out:
        sys.stdout.write(str(status))
    if status >= 400 and "--fail" in args:
        sys.exit(22)
    sys.exit(0)
if url.startswith("https://" + os.environ["STUB_FRONT"] + "/") and option("--cacert") is None:
    sys.stderr.write("certificate verify failed\n")
    sys.exit(60)
if "/manifests/" in url:
    base, rest = url.split("/v2/", 1)
    repository, tag = rest.rsplit("/manifests/", 1)
    digest = state["registry"].get(repository + ":" + tag)
    if digest is None:
        finish(404, "HTTP/1.1 404 Not Found\r\n\r\n")
    finish(200, "HTTP/1.1 200 OK\r\nDocker-Content-Digest: " + digest + "\r\n\r\n")
if url.endswith("/blobs/uploads/"):
    finish(405 if state["readonly"] else 202)
if url.endswith("/v2/"):
    finish(200)
if "/rke2/" in url and url.startswith("https://" + os.environ["STUB_FRONT"]):
    relative = url.split("/rke2/", 1)[1].replace("%2B", "+")
    path = os.path.join(os.environ["STUB_CACHE_ROOT"], "artifacts", "rke2", relative)
    finish(200 if os.path.isfile(path) else 404)
if url in state["downloads"]:
    with open(output, "wb") as handle:
        handle.write(state["downloads"][url].encode("latin-1"))
    finish(200)
sys.stderr.write("unexpected URL " + url + "\n")
sys.exit(7)
''',
    "docker": STUB_COMMON + r'''
state = load()
args = sys.argv[1:]
assert args[:3] == ["compose", "up", "-d"], args
state["readonly"] = os.environ.get("REGISTRY_READONLY") == "true"
log(state, "compose readonly=" + os.environ.get("REGISTRY_READONLY", "") + " " + " ".join(args[3:]))
save(state)
''',
    "findmnt": "#!/bin/sh\nprintf '%s\\n' \"$STUB_CACHE_ROOT\"\n",
    "df": "#!/bin/sh\nprintf 'Avail\\n50000000000\\n'\n",
    "flock": "#!/bin/sh\nexit 0\n",
}


def index_manifest(name: str) -> tuple[str, str]:
    """Return (raw index, linux/amd64 manifest digest) for one image."""
    amd64 = "sha256:" + hashlib.sha256(f"{name}-amd64".encode()).hexdigest()
    arm64 = "sha256:" + hashlib.sha256(f"{name}-arm64".encode()).hexdigest()
    raw = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {"digest": arm64, "platform": {"os": "linux", "architecture": "arm64"}},
            {"digest": amd64, "platform": {"os": "linux", "architecture": "amd64"}},
            {"digest": "sha256:" + "0" * 64, "platform": {"os": "unknown", "architecture": "unknown"}},
        ],
    })
    return raw, amd64


class RefreshBootstrapCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name) / "root"
        self.cache_root = self.root / "var/lib/inspace/bootstrap-cache"
        (self.cache_root / "state").mkdir(parents=True)
        (self.cache_root / "state" / "ready").write_text("ready\n")
        (self.root / "etc/inspace-cache/tls").mkdir(parents=True)
        (self.root / "etc/inspace-cache/tls/ca.crt").write_text("ca\n")
        (self.root / "opt/inspace-cache").mkdir(parents=True)
        (self.root / "usr/local/sbin").mkdir(parents=True)
        self.maintain = self.root / "usr/local/sbin/inspace-cache-maintain"
        self.maintain.write_text("#!/bin/sh\npinned_version=old\nfind artifacts/rke2 -atime +30 -exec rm -rf -- {} +\n")
        bin_dir = pathlib.Path(self.temp.name) / "bin"
        bin_dir.mkdir()
        for name, body in STUBS.items():
            path = bin_dir / name
            path.write_text(body)
            path.chmod(0o755)
        self.path = f"{bin_dir}:{os.environ['PATH']}"
        self.state_path = pathlib.Path(self.temp.name) / "state.json"

        pause_raw, self.pause_digest = index_manifest("pause")
        runtime_raw, self.runtime_digest = index_manifest("runtime")
        ccm_raw, self.ccm_digest = index_manifest("ccm")
        pause_source = "docker://docker.io/rancher/mirrored-pause@sha256:" + hashlib.sha256(pause_raw.encode()).hexdigest()
        self.runtime_source = "docker://docker.io/rancher/rke2-runtime@sha256:" + hashlib.sha256(runtime_raw.encode()).hexdigest()
        self.ccm_source = "docker://ghcr.io/thanet-s/inspace-cloud-controller-manager:1.2.0"
        self.manifest = pathlib.Path(self.temp.name) / "refresh.tsv"
        self.manifest.write_text(
            f"rke2\t{RKE2_VERSION}\t{RKE2_SHA}\n"
            f"image\t{pause_source}\trancher/mirrored-pause:3.10.2\n"
            f"image\t{self.runtime_source}\trancher/rke2-runtime:v1.36.5-rke2r1\n"
            f"image\t{self.ccm_source}\tthanet-s/inspace-cloud-controller-manager:1.2.0\n"
        )
        self.state = {
            "registry": {"rancher/mirrored-pause:3.10.2": self.pause_digest},
            "upstream": {pause_source: pause_raw, self.runtime_source: runtime_raw, self.ccm_source: ccm_raw},
            "downloads": {
                f"{RKE2_BASE}/rke2.linux-amd64.tar.gz": RKE2_ARCHIVE.decode("latin-1"),
                f"{RKE2_BASE}/sha256sum-amd64.txt": f"{RKE2_SHA}  rke2.linux-amd64.tar.gz\n",
            },
            "copy_digest": {},
            "readonly": True,
            "log": [],
        }
        self.save_state()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def save_state(self) -> None:
        self.state_path.write_text(json.dumps(self.state))

    def load_state(self) -> dict:
        return json.loads(self.state_path.read_text())

    def run_refresh(self, *args: str) -> subprocess.CompletedProcess[str]:
        environment = {
            "PATH": self.path,
            "STUB_STATE": str(self.state_path),
            "STUB_FRONT": FRONT,
            "STUB_CACHE_ROOT": str(self.cache_root),
            "INSPACE_CACHE_REFRESH_TEST_ROOT": str(self.root),
        }
        return subprocess.run(
            ["sh", str(SCRIPT), *(args or (str(self.manifest), FRONT))],
            env=environment, capture_output=True, text=True, timeout=120, check=False,
        )

    def copies(self, state: dict) -> list[str]:
        return [entry for entry in state["log"] if entry.startswith("copy ")]

    def test_adds_only_missing_entries_by_platform_digest_then_restores_read_only(self) -> None:
        result = self.run_refresh()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip().splitlines()[-1], "changed")
        state = self.load_state()
        self.assertEqual(state["registry"]["rancher/rke2-runtime:v1.36.5-rke2r1"], self.runtime_digest)
        self.assertEqual(state["registry"]["thanet-s/inspace-cloud-controller-manager:1.2.0"], self.ccm_digest)
        self.assertEqual(state["registry"]["rancher/mirrored-pause:3.10.2"], self.pause_digest)
        # A tag-sourced module image is copied by its resolved linux/amd64
        # digest, so a tag that moves during the refresh cannot be imported.
        self.assertEqual(self.copies(state), [
            f"copy docker://docker.io/rancher/rke2-runtime@{self.runtime_digest} "
            "docker://127.0.0.1:5000/rancher/rke2-runtime:v1.36.5-rke2r1",
            f"copy docker://ghcr.io/thanet-s/inspace-cloud-controller-manager@{self.ccm_digest} "
            "docker://127.0.0.1:5000/thanet-s/inspace-cloud-controller-manager:1.2.0",
        ])
        compose = [entry for entry in state["log"] if entry.startswith("compose ")]
        self.assertEqual(compose, [
            "compose readonly=false --wait registry",
            "compose readonly=true --wait --force-recreate registry nginx",
        ])
        self.assertTrue(state["readonly"])
        self.assertIn("curl POST http://127.0.0.1:5000/v2/inspace-cache-refresh-probe/blobs/uploads/", state["log"])
        for target in ("rancher/mirrored-pause/manifests/3.10.2", "thanet-s/inspace-cloud-controller-manager/manifests/1.2.0"):
            self.assertIn(f"curl HEAD https://{FRONT}/v2/{target}", state["log"])
        archive = self.cache_root / "artifacts/rke2" / RKE2_VERSION / "rke2.linux-amd64.tar.gz"
        self.assertEqual(archive.read_bytes(), RKE2_ARCHIVE)
        self.assertEqual(oct(archive.stat().st_mode & 0o777), "0o444")
        self.assertIn(f"curl HEAD https://{FRONT}/rke2/v1.36.5%2Brke2r1/rke2.linux-amd64.tar.gz", state["log"])
        self.assertNotIn("rm -rf", self.maintain.read_text())
        self.assertNotIn("artifacts/rke2", self.maintain.read_text())

    def test_second_run_is_an_unchanged_no_op(self) -> None:
        self.assertEqual(self.run_refresh().returncode, 0)
        state = self.load_state()
        state["log"] = []
        self.state = state
        self.save_state()
        result = self.run_refresh()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip().splitlines()[-1], "unchanged")
        state = self.load_state()
        self.assertEqual(self.copies(state), [])
        self.assertFalse([entry for entry in state["log"] if entry.startswith("compose ")])

    def test_refuses_to_overwrite_a_tag_that_holds_another_digest(self) -> None:
        self.state["registry"]["thanet-s/inspace-cloud-controller-manager:1.2.0"] = "sha256:" + "f" * 64
        self.save_state()
        result = self.run_refresh()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to overwrite", result.stderr)
        state = self.load_state()
        self.assertEqual(self.copies(state), [])
        self.assertFalse([entry for entry in state["log"] if entry.startswith("compose ")])
        self.assertFalse((self.cache_root / "artifacts/rke2" / RKE2_VERSION).exists())
        self.assertEqual(state["registry"]["thanet-s/inspace-cloud-controller-manager:1.2.0"], "sha256:" + "f" * 64)

    def test_refuses_a_pinned_source_whose_manifest_digest_differs(self) -> None:
        self.state["upstream"][self.runtime_source] = index_manifest("tampered")[0]
        self.save_state()
        result = self.run_refresh()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.copies(self.load_state()), [])

    def test_rejects_a_malformed_manifest_before_any_network_access(self) -> None:
        self.manifest.write_text(self.manifest.read_text() + "image\tdocker://evil.example/x:latest; rm -rf /\tx:1\n")
        result = self.run_refresh()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("malformed", result.stderr)
        self.assertEqual(self.load_state()["log"], [])

    def test_rejects_an_unexpected_cache_endpoint(self) -> None:
        result = self.run_refresh(str(self.manifest), "evil.example:8443")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.load_state()["log"], [])

    def test_rejects_an_rke2_archive_with_the_wrong_checksum(self) -> None:
        self.state["downloads"][f"{RKE2_BASE}/rke2.linux-amd64.tar.gz"] = "tampered"
        self.save_state()
        result = self.run_refresh()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum", result.stderr)
        self.assertFalse((self.cache_root / "artifacts/rke2" / RKE2_VERSION / "rke2.linux-amd64.tar.gz").exists())

    def test_refuses_to_replace_a_different_cached_rke2_archive(self) -> None:
        directory = self.cache_root / "artifacts/rke2" / RKE2_VERSION
        directory.mkdir(parents=True)
        (directory / "rke2.linux-amd64.tar.gz").write_bytes(b"other bytes")
        result = self.run_refresh()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to overwrite", result.stderr)
        self.assertEqual((directory / "rke2.linux-amd64.tar.gz").read_bytes(), b"other bytes")

    def test_failed_readback_still_restores_the_read_only_registry(self) -> None:
        self.state["copy_digest"]["rancher/rke2-runtime:v1.36.5-rke2r1"] = "sha256:" + "e" * 64
        self.save_state()
        result = self.run_refresh()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("readback", result.stderr)
        state = self.load_state()
        self.assertTrue(state["readonly"])
        self.assertEqual(
            [entry for entry in state["log"] if entry.startswith("compose ")][-1],
            "compose readonly=true --wait --force-recreate registry nginx",
        )

    def test_requires_a_ready_cache(self) -> None:
        (self.cache_root / "state" / "ready").unlink()
        result = self.run_refresh()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not ready", result.stderr)

    def test_installed_maintenance_script_is_the_bootstrap_contract(self) -> None:
        source = (ROOT / "modules/cloud-provider/pkg/bootstrap/cache_cloudinit.go").read_text()
        match = re.search(r"const cacheMaintenanceScript = `([^`]*)`", source)
        self.assertIsNotNone(match)
        self.assertEqual(self.run_refresh().returncode, 0)
        self.assertEqual(self.maintain.read_text(), match.group(1))
        self.assertEqual(oct(self.maintain.stat().st_mode & 0o777), "0o700")


if __name__ == "__main__":
    unittest.main()
