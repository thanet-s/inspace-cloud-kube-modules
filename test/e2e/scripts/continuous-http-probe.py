#!/usr/bin/env python3
"""Fail if a retained NodeLB HTTP frontend drops during a policy mutation."""

import argparse
import json
import pathlib
import time
import urllib.request


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--stop-file", required=True)
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--interval", type=float, default=0.25)
    parser.add_argument("--request-timeout", type=float, default=3.0)
    parser.add_argument("--overall-timeout", type=float, default=1800.0)
    args = parser.parse_args()
    if args.interval <= 0 or args.request_timeout <= 0 or args.overall_timeout <= 0:
        raise SystemExit("probe intervals and timeouts must be positive")

    stop_file = pathlib.Path(args.stop_file)
    ready_file = pathlib.Path(args.ready_file)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    started = time.monotonic()
    successes = 0
    while not stop_file.exists():
        elapsed = time.monotonic() - started
        if elapsed >= args.overall_timeout:
            raise SystemExit(f"continuous probe timed out after {elapsed:.3f}s")
        try:
            request = urllib.request.Request(
                args.url,
                headers={"User-Agent": "inspace-rke2-e2e-node-lb-continuity/1"},
            )
            with opener.open(request, timeout=args.request_timeout) as response:
                body = response.read().decode("utf-8").strip()
                status = response.status
        except Exception as error:  # The concrete exception is part of the diagnostic.
            raise SystemExit(
                f"retained NodeLB frontend failed after {successes} successes: {error}"
            ) from error
        if status != 200 or body != args.expected:
            raise SystemExit(
                "retained NodeLB frontend changed after "
                f"{successes} successes: status={status} body={body!r}"
            )
        successes += 1
        if successes == 4:
            ready_file.touch(mode=0o600, exist_ok=True)
        time.sleep(args.interval)

    elapsed = time.monotonic() - started
    if successes < 4:
        raise SystemExit(f"continuous probe stopped too early after {successes} successes")
    print(json.dumps({"durationSeconds": round(elapsed, 3), "successes": successes}, sort_keys=True))


if __name__ == "__main__":
    main()
