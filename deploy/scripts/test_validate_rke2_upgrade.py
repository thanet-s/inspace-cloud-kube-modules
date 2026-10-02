#!/usr/bin/env python3
"""Unit tests for validate_rke2_upgrade.py's version-transition safety guard."""

from __future__ import annotations

import unittest

import validate_rke2_upgrade
from validate_rke2_upgrade import GA, UnsafeRKE2Transition, parse_version, validate_transition


class ParseVersionTests(unittest.TestCase):
    def test_parses_exact_rke2_version(self) -> None:
        self.assertEqual(parse_version("v1.36.4+rke2r1"), (1, 36, 4, GA, 1))

    def test_parses_a_released_candidate_before_its_ga(self) -> None:
        released = validate_rke2_upgrade.RELEASED_PRERELEASES
        self.assertEqual(parse_version("v1.36.5-rc2+rke2r1", released), (1, 36, 5, 2, 1))
        self.assertLess(parse_version("v1.36.5-rc2+rke2r1", released), parse_version("v1.36.5+rke2r1"))
        self.assertGreater(parse_version("v1.36.5-rc2+rke2r1", released), parse_version("v1.36.4+rke2r1"))

    def test_rejects_malformed_version(self) -> None:
        for value in ("1.36.4+rke2r1", "v1.36.4", "v1.36.4-rke2r1", "vX.Y.Z+rke2r1", ""):
            with self.assertRaises(UnsafeRKE2Transition):
                parse_version(value)

    def test_rejects_unaudited_release_candidates(self) -> None:
        for value in ("v1.36.5-rc1+rke2r1", "v1.36.5-rc2+rke2r1", "v1.36.5-rc2+rke2r2", "v1.37.1-rc2+rke2r1", "v1.36.5-rc2"):
            with self.assertRaises(UnsafeRKE2Transition):
                parse_version(value)


class ValidateTransitionTests(unittest.TestCase):
    def test_same_version_is_allowed(self) -> None:
        validate_transition("v1.36.4+rke2r1", "v1.36.4+rke2r1", forced=False)

    def test_patch_upgrade_is_allowed(self) -> None:
        validate_transition("v1.36.4+rke2r1", "v1.36.5+rke2r1", forced=False)

    def test_single_minor_upgrade_is_allowed(self) -> None:
        validate_transition("v1.36.4+rke2r1", "v1.37.0+rke2r1", forced=False)

    def test_multi_minor_skip_is_refused(self) -> None:
        with self.assertRaises(UnsafeRKE2Transition):
            validate_transition("v1.36.4+rke2r1", "v1.38.0+rke2r1", forced=False)

    def test_multi_minor_skip_allowed_when_forced(self) -> None:
        validate_transition("v1.36.4+rke2r1", "v1.38.0+rke2r1", forced=True)

    def test_major_version_change_is_refused(self) -> None:
        with self.assertRaises(UnsafeRKE2Transition):
            validate_transition("v1.36.4+rke2r1", "v2.0.0+rke2r1", forced=False)

    def test_downgrade_is_refused(self) -> None:
        with self.assertRaises(UnsafeRKE2Transition):
            validate_transition("v1.36.4+rke2r1", "v1.35.9+rke2r1", forced=False)

    def test_downgrade_allowed_when_forced(self) -> None:
        validate_transition("v1.36.4+rke2r1", "v1.35.9+rke2r1", forced=True)

    def test_patch_downgrade_is_refused(self) -> None:
        with self.assertRaises(UnsafeRKE2Transition):
            validate_transition("v1.36.4+rke2r1", "v1.36.3+rke2r1", forced=False)

    def test_ga_patch_upgrade_to_the_audited_release_is_allowed(self) -> None:
        validate_transition("v1.36.4+rke2r1", "v1.36.5+rke2r1", forced=False)

    def test_released_candidate_upgrades_to_its_ga(self) -> None:
        validate_transition("v1.36.5-rc2+rke2r1", "v1.36.5+rke2r1", forced=False)

    def test_released_candidate_stays_an_upgrade_source_after_its_pin_moves(self) -> None:
        # Clusters a published release installed on the candidate must still
        # upgrade off it once the cache pin is GA.
        validate_transition("v1.36.5-rc2+rke2r1", "v1.37.0+rke2r1", forced=False)
        with self.assertRaises(UnsafeRKE2Transition):
            validate_transition("v1.36.5-rc2+rke2r1", "v1.38.0+rke2r1", forced=False)

    def test_released_candidate_is_no_target_after_its_pin_moves(self) -> None:
        for current in ("v1.36.4+rke2r1", "v1.36.5+rke2r1", "v1.36.5-rc2+rke2r1"):
            for forced in (False, True):
                with self.assertRaises(UnsafeRKE2Transition):
                    validate_transition(current, "v1.36.5-rc2+rke2r1", forced=forced)

    def test_unreleased_candidate_is_no_upgrade_source(self) -> None:
        with self.assertRaises(UnsafeRKE2Transition):
            validate_transition("v1.36.5-rc1+rke2r1", "v1.36.5+rke2r1", forced=False)

    def test_malformed_current_version_is_refused(self) -> None:
        with self.assertRaises(UnsafeRKE2Transition):
            validate_transition("not-a-version", "v1.36.4+rke2r1", forced=False)


if __name__ == "__main__":
    unittest.main()
