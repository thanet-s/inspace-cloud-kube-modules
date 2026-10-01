#!/usr/bin/env python3
"""Offline tests for templates/post-upgrade-reboot.sh."""

from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "templates" / "post-upgrade-reboot.sh"
BOOT_ID = "0f0e0d0c-0b0a-0908-0706-050403020100"


class PostUpgradeRebootTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = pathlib.Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "commands.log"
        self.log.write_text("")
        (self.root / "proc/sys/kernel/random").mkdir(parents=True)
        (self.root / "run").mkdir()
        (self.root / "proc/sys/kernel/random/boot_id").write_text(BOOT_ID + "\n")
        self.stub("cloud-init", 'printf "cloud-init %s\\n" "$*" >>"$COMMAND_LOG"')
        self.stub("systemd-run", 'printf "systemd-run %s\\n" "$*" >>"$COMMAND_LOG"')

    def stub(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)

    def reboot_required(self) -> None:
        (self.root / "run/reboot-required").write_text("*** System restart required ***\n")

    def run_script(self, command: str) -> subprocess.CompletedProcess[str]:
        env = dict(
            os.environ,
            PATH=f"{self.bin}:{os.environ['PATH']}",
            INSPACE_POST_UPGRADE_TEST_ROOT=str(self.root),
            COMMAND_LOG=str(self.log),
        )
        return subprocess.run(["sh", str(SCRIPT), command], capture_output=True, text=True, env=env, check=False)

    def marker(self) -> pathlib.Path:
        return self.root / "var/lib/inspace/post-upgrade-reboot.done"

    def test_check_needs_a_reboot_only_when_one_is_pending(self) -> None:
        self.reboot_required()
        result = self.run_script("check")
        self.assertEqual((result.returncode, result.stdout), (0, "needed"), result.stderr)

    def test_check_is_done_without_a_pending_reboot(self) -> None:
        result = self.run_script("check")
        self.assertEqual((result.returncode, result.stdout), (0, "done"), result.stderr)

    def test_check_is_done_when_the_marker_exists_even_if_a_reboot_is_pending(self) -> None:
        self.reboot_required()
        self.assertEqual(self.run_script("mark").returncode, 0)
        self.assertTrue(self.marker().is_file())
        self.assertEqual(self.run_script("check").stdout, "done")

    def test_reboot_waits_for_cloud_init_then_schedules_one_delayed_reboot(self) -> None:
        result = self.run_script("reboot")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), BOOT_ID)
        self.assertEqual(
            self.log.read_text(),
            "cloud-init status --wait\nsystemd-run --on-active=5 /bin/systemctl reboot\n",
        )

    def test_reboot_does_not_wait_for_a_cloud_init_that_ended_in_error(self) -> None:
        self.stub("cloud-init", 'printf "cloud-init %s\\n" "$*" >>"$COMMAND_LOG"; exit 2')
        result = self.run_script("reboot")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("systemd-run", self.log.read_text())

    def test_reboot_surfaces_a_systemd_run_failure(self) -> None:
        self.stub("systemd-run", 'echo "Failed to start transient timer unit: Access denied" >&2; exit 1')
        result = self.run_script("reboot")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Access denied", result.stderr)
        self.assertNotIn("Access denied", result.stdout)

    def test_unknown_subcommand_fails(self) -> None:
        self.assertEqual(self.run_script("nope").returncode, 2)


if __name__ == "__main__":
    unittest.main()
