#!/usr/bin/env python3
"""Atomically update one top-level field in the E2E ownership journal."""

import json
import pathlib
import sys

from durable_io import atomic_write_json


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: state-update.py STATE KEY JSON_VALUE")
    path = pathlib.Path(sys.argv[1])
    key = sys.argv[2]
    value = json.loads(sys.argv[3])
    state = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(state, dict) or not key or "." in key:
        raise SystemExit("state and top-level key must be valid")
    state[key] = value
    atomic_write_json(path, state)


if __name__ == "__main__":
    main()
