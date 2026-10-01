#!/usr/bin/env python3
"""Offline tests for templates/post-upgrade-reboot.sh."""

from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "templates" / "post-upgrade-reboot.sh"
BOOT_TIME = 1_700_000_000
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
        (self.root / "proc/stat").write_text(f"cpu  1 2 3\nbtime {BOOT_TIME}\nprocesses 9\n")
        (self.root / "proc/sys/kernel/random/boot_id").write_text(BOOT_ID + "\n")
        (self.root / "var/lib/cloud/instance/sem").mkdir(parents=True)
        stub = self.bin / "systemd-run"
        stub.write_text('#!/bin/sh\nprintf "systemd-run %s\\n" "$*" >>"$COMMAND_LOG"\n')
        stub.chmod(0o755)

    def semaphore(self, mtime: int) -> None:
        path = self.root / "var/lib/cloud/instance/sem/config_scripts_user"
        path.write_text("")
        os.utime(path, (mtime, mtime))

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

    def test_check_needs_a_reboot_while_still_in_the_cloud_init_boot(self) -> None:
        self.semaphore(BOOT_TIME + 120)
        result = self.run_script("check")
        self.assertEqual((result.returncode, result.stdout), (0, "needed"), result.stderr)

    def test_check_is_done_after_a_reboot_since_cloud_init_ran(self) -> None:
        self.semaphore(BOOT_TIME - 3600)
        self.assertEqual(self.run_script("check").stdout, "done")

    def test_check_is_done_when_the_marker_exists(self) -> None:
        self.semaphore(BOOT_TIME + 120)
        self.assertEqual(self.run_script("mark").returncode, 0)
        self.assertTrue(self.marker().is_file())
        self.assertEqual(self.run_script("check").stdout, "done")

    def test_check_is_done_without_a_cloud_init_semaphore(self) -> None:
        self.assertEqual(self.run_script("check").stdout, "done")

    def test_reboot_prints_the_boot_id_and_schedules_one_delayed_reboot(self) -> None:
        result = self.run_script("reboot")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), BOOT_ID)
        self.assertEqual(self.log.read_text(), "systemd-run --on-active=5 /bin/systemctl reboot\n")

    def test_unknown_subcommand_fails(self) -> None:
        self.assertEqual(self.run_script("nope").returncode, 2)


if __name__ == "__main__":
    unittest.main()
