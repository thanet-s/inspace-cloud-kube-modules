#!/usr/bin/env python3
"""Unit tests for the retained NodeLB continuity probe."""

import importlib.util
import pathlib
import unittest


SCRIPT_DIRECTORY = pathlib.Path(__file__).resolve().parent / "scripts"
SPEC = importlib.util.spec_from_file_location(
    "continuous_http_probe",
    SCRIPT_DIRECTORY / "continuous-http-probe.py",
)
assert SPEC is not None and SPEC.loader is not None
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class ScriptedFrontend:
    """Replays one outcome per request, then stops the probe."""

    def __init__(self, clock: FakeClock, outcomes: list, request_seconds: float = 0.0) -> None:
        self.clock = clock
        self.outcomes = list(outcomes)
        self.request_seconds = request_seconds
        self.ready = False

    def fetch(self):
        self.clock.now += self.request_seconds
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def stopped(self) -> bool:
        return not self.outcomes

    def mark_ready(self) -> None:
        self.ready = True


def run(outcomes: list, max_outage: float = 10.0, request_seconds: float = 0.0) -> dict:
    clock = FakeClock()
    frontend = ScriptedFrontend(clock, outcomes, request_seconds)
    return PROBE.run_probe(
        fetch=frontend.fetch,
        stopped=frontend.stopped,
        mark_ready=frontend.mark_ready,
        expected="marker",
        interval=0.25,
        overall_timeout=7200.0,
        max_outage=max_outage,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )


OK = (200, "marker")


class ContinuityProbeTests(unittest.TestCase):
    def test_tolerates_one_transport_timeout_inside_the_outage_budget(self) -> None:
        result = run([OK] * 4 + [TimeoutError("timed out")] + [OK] * 4, request_seconds=3.0)
        self.assertEqual(result["successes"], 8)
        self.assertEqual(result["transportFailures"], 1)
        self.assertLessEqual(result["longestOutageSeconds"], 10.0)

    def test_fails_when_the_frontend_stays_unreachable_beyond_the_budget(self) -> None:
        outcomes = [OK] * 4 + [TimeoutError("timed out")] * 5 + [OK]
        with self.assertRaisesRegex(SystemExit, "unreachable for"):
            run(outcomes, max_outage=10.0, request_seconds=3.0)

    def test_fails_immediately_on_a_wrong_backend_response(self) -> None:
        with self.assertRaisesRegex(SystemExit, "changed after 4 successes"):
            run([OK] * 4 + [(200, "other-backend")] + [OK] * 4)

    def test_fails_immediately_on_a_non_200_response(self) -> None:
        with self.assertRaisesRegex(SystemExit, "status=503"):
            run([OK] * 4 + [(503, "marker")])

    def test_requires_four_successes_before_stop(self) -> None:
        with self.assertRaisesRegex(SystemExit, "stopped too early"):
            run([OK] * 3)

    def test_zero_outage_budget_keeps_the_original_strict_behavior(self) -> None:
        with self.assertRaisesRegex(SystemExit, "unreachable for"):
            run([OK] * 4 + [TimeoutError("timed out")] + [OK] * 4, max_outage=0.0)


if __name__ == "__main__":
    unittest.main()
