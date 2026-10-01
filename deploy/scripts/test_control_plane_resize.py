#!/usr/bin/env python3
"""Offline tests for control_plane_resize.py: the resize decision and journal."""

from __future__ import annotations

import copy
import io
import json
import os
import pathlib
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import control_plane_resize as resize

NAMES = ["unit-cp0", "unit-cp1", "unit-cp2"]


def journal() -> dict:
    return {
        "schema": "inspace-deploy-state-v1",
        "clusterName": "unit",
        "controlPlanes": [{"name": name, "privateIPv4": f"10.0.0.{index + 10}"} for index, name in enumerate(NAMES)],
    }


class ClassifyTests(unittest.TestCase):
    def test_matching_inventory_needs_no_resize(self) -> None:
        result = resize.classify(journal(), (2, 4096), (2, 4096))
        self.assertFalse(result["resizeNeeded"])
        self.assertEqual(result["pending"], [])

    def test_journal_without_the_key_falls_back_to_the_cluster_yaml_size(self) -> None:
        result = resize.classify(journal(), (2, 4096), (4, 8192))
        self.assertTrue(result["resizeNeeded"])
        self.assertEqual(result["recorded"], {"vcpu": 2, "memoryMiB": 4096})
        self.assertEqual(result["target"], {"vcpu": 4, "memoryMiB": 8192})
        self.assertEqual(result["pending"], NAMES)

    def test_recorded_size_wins_over_the_cluster_yaml(self) -> None:
        state = journal() | {"controlPlaneMachine": {"vcpu": 2, "memoryMiB": 6144}}
        self.assertFalse(resize.classify(state, (2, 4096), (2, 6144))["resizeNeeded"])
        with self.assertRaisesRegex(resize.ResizeError, "can only grow"):
            resize.classify(state, (2, 4096), (2, 4096))

    def test_growing_either_dimension_is_a_valid_resize(self) -> None:
        for inventory in ((4, 4096), (2, 8192), (8, 16384)):
            self.assertTrue(resize.classify(journal(), (2, 4096), inventory)["resizeNeeded"], inventory)

    def test_shrinking_any_dimension_is_refused_with_a_clear_message(self) -> None:
        for spec, inventory in (((4, 8192), (2, 8192)), ((4, 8192), (4, 4096)), ((4, 8192), (2, 4096))):
            with self.assertRaises(resize.ResizeError, msg=str((spec, inventory))):
                resize.classify(journal(), spec, inventory)
        with self.assertRaisesRegex(resize.ResizeError, "shrinking is not supported"):
            resize.classify(journal(), (4, 8192), (2, 8192))

    def test_a_mixed_grow_and_shrink_is_refused(self) -> None:
        with self.assertRaisesRegex(resize.ResizeError, "can only grow"):
            resize.classify(journal(), (2, 8192), (4, 4096))

    def test_inventory_outside_the_preflight_bounds_is_refused(self) -> None:
        for inventory in ((1, 4096), (17, 8192), (2, 65537), (2, 4095)):
            with self.assertRaisesRegex(resize.ResizeError, "outside the supported"):
                resize.classify(journal(), (2, 4096), inventory)

    def test_malformed_recorded_size_is_refused(self) -> None:
        state = journal() | {"controlPlaneMachine": {"vcpu": "2", "memoryMiB": 4096}}
        with self.assertRaisesRegex(resize.ResizeError, "whole number"):
            resize.classify(state, (2, 4096), (2, 4096))

    def test_a_resize_in_progress_resumes_and_skips_completed_servers(self) -> None:
        state = journal()
        resize.begin(state, (2, 6144))
        resize.slot_start(state, "unit-cp0")
        resize.slot_done(state, "unit-cp0")
        resize.slot_start(state, "unit-cp1")
        result = resize.classify(state, (2, 4096), (2, 6144))
        self.assertTrue(result["resizeNeeded"] and result["resuming"])
        self.assertEqual(result["inProgress"], "unit-cp1")
        self.assertEqual(result["pending"], ["unit-cp1", "unit-cp2"])

    def test_inventory_that_contradicts_a_resize_in_progress_is_refused(self) -> None:
        state = journal()
        resize.begin(state, (2, 6144))
        resize.slot_start(state, "unit-cp0")
        for inventory in ((2, 4096), (2, 8192)):
            with self.assertRaisesRegex(resize.ResizeError, "in progress"):
                resize.classify(state, (2, 4096), inventory)

    def test_a_journal_naming_unknown_servers_is_refused(self) -> None:
        state = journal()
        resize.begin(state, (2, 6144))
        state["controlPlaneResize"]["completed"] = ["other-cp9"]
        with self.assertRaisesRegex(resize.ResizeError, "unknown or repeated"):
            resize.classify(state, (2, 4096), (2, 6144))


class ModeAndRetargetTests(unittest.TestCase):
    def test_report_mode_never_raises_so_status_and_destroy_keep_working(self) -> None:
        for spec, inventory in (((4, 8192), (2, 8192)), ((2, 4096), (1, 4096))):
            result = resize.classify(journal(), spec, inventory, enforce=False)
            self.assertFalse(result["resizeNeeded"])
            self.assertTrue(result["error"])
        state = journal()
        resize.begin(state, (2, 6144))
        resize.slot_done(state, "unit-cp0")
        result = resize.classify(state, (2, 4096), (2, 8192), enforce=False)
        self.assertIn("in progress", result["error"])

    def test_report_mode_matches_enforce_mode_when_valid(self) -> None:
        enforced = resize.classify(journal(), (2, 4096), (2, 6144))
        reported = resize.classify(journal(), (2, 4096), (2, 6144), enforce=False)
        self.assertEqual(reported, enforced | {"error": ""})

    def test_a_resize_record_without_progress_can_be_retargeted(self) -> None:
        state = journal()
        resize.begin(state, (2, 6144))
        result = resize.classify(state, (2, 4096), (4, 8192))
        self.assertTrue(result["resizeNeeded"] and result["staleResize"] and not result["resuming"])
        self.assertEqual(result["target"], {"vcpu": 4, "memoryMiB": 8192})
        resize.begin(state, (4, 8192))
        self.assertEqual(state["controlPlaneResize"]["target"], {"vcpu": 4, "memoryMiB": 8192})

    def test_retargeting_is_refused_once_a_server_started_or_completed(self) -> None:
        for step in (resize.slot_start, resize.slot_done):
            state = journal()
            resize.begin(state, (2, 6144))
            step(state, "unit-cp0")
            with self.assertRaisesRegex(resize.ResizeError, "different size"):
                resize.begin(state, (4, 8192))

    def test_clear_drops_a_record_without_progress_only(self) -> None:
        state = journal()
        resize.begin(state, (2, 6144))
        resize.clear(state)
        self.assertNotIn("controlPlaneResize", state)
        self.assertFalse(resize.classify(state, (2, 4096), (2, 4096))["resizeNeeded"])
        resize.begin(state, (2, 6144))
        resize.slot_start(state, "unit-cp0")
        with self.assertRaisesRegex(resize.ResizeError, "progress"):
            resize.clear(state)

    def test_an_unneeded_resize_reports_a_stale_record(self) -> None:
        state = journal()
        resize.begin(state, (2, 6144))
        result = resize.classify(state, (2, 4096), (2, 4096))
        self.assertFalse(result["resizeNeeded"])
        self.assertTrue(result["staleResize"])


class JournalTests(unittest.TestCase):
    def test_full_lifecycle_records_the_target_and_clears_progress(self) -> None:
        state = journal()
        resize.begin(state, (2, 6144))
        self.assertEqual(state["controlPlaneResize"], {"target": {"vcpu": 2, "memoryMiB": 6144}, "inProgress": "", "completed": []})
        for name in NAMES:
            resize.slot_start(state, name)
            self.assertEqual(state["controlPlaneResize"]["inProgress"], name)
            resize.slot_done(state, name)
        resize.finish(state)
        self.assertEqual(state["controlPlaneMachine"], {"vcpu": 2, "memoryMiB": 6144})
        self.assertNotIn("controlPlaneResize", state)
        self.assertFalse(resize.classify(state, (2, 4096), (2, 6144))["resizeNeeded"])

    def test_already_resized_servers_can_complete_without_a_start(self) -> None:
        # Out-of-band resize: every VM is already at target, so no slot starts.
        state = journal()
        resize.begin(state, (2, 6144))
        for name in NAMES:
            resize.slot_done(state, name)
        resize.finish(state)
        self.assertEqual(state["controlPlaneMachine"], {"vcpu": 2, "memoryMiB": 6144})

    def test_finish_refuses_while_a_server_is_pending(self) -> None:
        state = journal()
        resize.begin(state, (2, 6144))
        resize.slot_done(state, "unit-cp0")
        with self.assertRaisesRegex(resize.ResizeError, "unit-cp1"):
            resize.finish(state)
        self.assertIn("controlPlaneResize", state)

    def test_only_one_server_is_in_progress_at_a_time(self) -> None:
        state = journal()
        resize.begin(state, (2, 6144))
        resize.slot_start(state, "unit-cp0")
        with self.assertRaisesRegex(resize.ResizeError, "still mid-resize"):
            resize.slot_start(state, "unit-cp1")

    def test_a_completed_server_cannot_restart_and_done_is_idempotent(self) -> None:
        state = journal()
        resize.begin(state, (2, 6144))
        resize.slot_done(state, "unit-cp0")
        resize.slot_done(state, "unit-cp0")
        self.assertEqual(state["controlPlaneResize"]["completed"], ["unit-cp0"])
        with self.assertRaisesRegex(resize.ResizeError, "already completed"):
            resize.slot_start(state, "unit-cp0")

    def test_begin_is_idempotent_for_the_same_target_and_refuses_another(self) -> None:
        state = journal()
        resize.begin(state, (2, 6144))
        resize.slot_done(state, "unit-cp0")
        before = copy.deepcopy(state)
        resize.begin(state, (2, 6144))
        self.assertEqual(state, before)
        with self.assertRaisesRegex(resize.ResizeError, "different size"):
            resize.begin(state, (4, 8192))

    def test_begin_refuses_shrinking_the_recorded_size(self) -> None:
        state = journal() | {"controlPlaneMachine": {"vcpu": 4, "memoryMiB": 8192}}
        with self.assertRaisesRegex(resize.ResizeError, "only grow"):
            resize.begin(state, (2, 8192))

    def test_unknown_server_names_are_refused(self) -> None:
        state = journal()
        resize.begin(state, (2, 6144))
        with self.assertRaisesRegex(resize.ResizeError, "not a journaled"):
            resize.slot_start(state, "other-cp0")

    def test_operations_need_a_begun_resize(self) -> None:
        with self.assertRaisesRegex(resize.ResizeError, "run begin first"):
            resize.slot_done(journal(), "unit-cp0")


class CommandLineTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = pathlib.Path(self._tmp.name) / "state.json"
        self.state.write_text(json.dumps(journal()))

    def run_cli(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = resize.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_classify_prints_json_and_leaves_the_journal_untouched(self) -> None:
        before = self.state.read_text()
        code, out, _ = self.run_cli(
            "classify", "--state", str(self.state), "--spec-vcpu", "2", "--spec-memory-mib", "4096",
            "--inventory-vcpu", "2", "--inventory-memory-mib", "6144",
        )
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)["resizeNeeded"])
        self.assertEqual(self.state.read_text(), before)

    def test_classify_failure_exits_nonzero_with_the_message_on_stderr(self) -> None:
        code, out, err = self.run_cli(
            "classify", "--state", str(self.state), "--spec-vcpu", "4", "--spec-memory-mib", "8192",
            "--inventory-vcpu", "2", "--inventory-memory-mib", "8192",
        )
        self.assertEqual((code, out), (1, ""))
        self.assertIn("shrinking is not supported", err)

    def test_journal_commands_persist_atomically_with_mode_0600(self) -> None:
        for args in (
            ("begin", "--target-vcpu", "2", "--target-memory-mib", "6144"),
            ("slot-start", "--name", "unit-cp0"),
            ("slot-done", "--name", "unit-cp0"),
        ):
            code, out, err = self.run_cli(args[0], "--state", str(self.state), *args[1:])
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(out), json.loads(self.state.read_text()))
        self.assertEqual(json.loads(self.state.read_text())["controlPlaneResize"]["completed"], ["unit-cp0"])
        if os.name == "posix":
            self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
        self.assertEqual([item.name for item in self.state.parent.iterdir()], ["state.json"])

    def test_classify_report_mode_exits_zero_with_the_error_in_the_json(self) -> None:
        code, out, _ = self.run_cli(
            "classify", "--mode", "report", "--state", str(self.state), "--spec-vcpu", "4", "--spec-memory-mib", "8192",
            "--inventory-vcpu", "2", "--inventory-memory-mib", "8192",
        )
        self.assertEqual(code, 0)
        self.assertIn("shrinking is not supported", json.loads(out)["error"])

    def test_a_refused_journal_command_leaves_the_file_unchanged(self) -> None:
        before = self.state.read_text()
        code, _, err = self.run_cli("slot-done", "--state", str(self.state), "--name", "unit-cp0")
        self.assertEqual(code, 1)
        self.assertIn("run begin first", err)
        self.assertEqual(self.state.read_text(), before)

    def test_a_foreign_file_is_not_a_journal(self) -> None:
        self.state.write_text('{"schema": "other"}')
        code, _, err = self.run_cli("finish", "--state", str(self.state))
        self.assertEqual(code, 1)
        self.assertIn("not a deployment journal", err)


if __name__ == "__main__":
    unittest.main()
