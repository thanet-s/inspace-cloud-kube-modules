#!/usr/bin/env python3
"""Fail if a retained NodeLB HTTP frontend drops during a policy mutation.

A wrong status or body fails immediately: it means traffic reached the wrong
backend. A transport error or timeout is tolerated only while the frontend
recovers within --max-outage seconds, so a single packet lost on the public
path from the runner cannot fail a run, while a real datapath outage still
does.
"""

import argparse
import json
import pathlib
import time
import urllib.request
from typing import Callable


def run_probe(
    *,
    fetch: Callable[[], tuple[int, str]],
    stopped: Callable[[], bool],
    mark_ready: Callable[[], None],
    expected: str,
    interval: float,
    overall_timeout: float,
    max_outage: float,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    started = monotonic()
    successes = 0
    transport_failures = 0
    longest_outage = 0.0
    outage_started: float | None = None
    while not stopped():
        attempt_started = monotonic()
        elapsed = attempt_started - started
        if elapsed >= overall_timeout:
            raise SystemExit(f"continuous probe timed out after {elapsed:.3f}s")
        try:
            status, body = fetch()
        except Exception as error:  # The concrete exception is part of the diagnostic.
            transport_failures += 1
            if outage_started is None:
                outage_started = attempt_started
            outage = monotonic() - outage_started
            longest_outage = max(longest_outage, outage)
            if max_outage <= 0 or outage > max_outage:
                raise SystemExit(
                    f"retained NodeLB frontend unreachable for {outage:.3f}s "
                    f"after {successes} successes: {error}"
                ) from error
            sleep(interval)
            continue
        if status != 200 or body != expected:
            raise SystemExit(
                "retained NodeLB frontend changed after "
                f"{successes} successes: status={status} body={body!r}"
            )
        if outage_started is not None:
            longest_outage = max(longest_outage, monotonic() - outage_started)
            outage_started = None
        successes += 1
        if successes == 4:
            mark_ready()
        sleep(interval)

    if successes < 4:
        raise SystemExit(f"continuous probe stopped too early after {successes} successes")
    return {
        "durationSeconds": round(monotonic() - started, 3),
        "longestOutageSeconds": round(longest_outage, 3),
        "successes": successes,
        "transportFailures": transport_failures,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--stop-file", required=True)
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--interval", type=float, default=0.25)
    parser.add_argument("--request-timeout", type=float, default=3.0)
    parser.add_argument("--overall-timeout", type=float, default=1800.0)
    parser.add_argument("--max-outage", type=float, default=10.0)
    args = parser.parse_args()
    if args.interval <= 0 or args.request_timeout <= 0 or args.overall_timeout <= 0:
        raise SystemExit("probe intervals and timeouts must be positive")
    if args.max_outage < 0:
        raise SystemExit("probe outage budget cannot be negative")

    stop_file = pathlib.Path(args.stop_file)
    ready_file = pathlib.Path(args.ready_file)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def fetch() -> tuple[int, str]:
        request = urllib.request.Request(
            args.url,
            headers={"User-Agent": "inspace-rke2-e2e-node-lb-continuity/1"},
        )
        with opener.open(request, timeout=args.request_timeout) as response:
            return response.status, response.read().decode("utf-8").strip()

    result = run_probe(
        fetch=fetch,
        stopped=stop_file.exists,
        mark_ready=lambda: ready_file.touch(mode=0o600, exist_ok=True),
        expected=args.expected,
        interval=args.interval,
        overall_timeout=args.overall_timeout,
        max_outage=args.max_outage,
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
