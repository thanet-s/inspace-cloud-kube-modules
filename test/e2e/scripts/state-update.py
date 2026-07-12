#!/usr/bin/env python3
"""Atomically update one top-level field in the E2E ownership journal."""

import json
import os
import pathlib
import sys
import tempfile


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
    write_json(path, state)


def write_json(path: pathlib.Path, value: object) -> None:
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


if __name__ == "__main__":
    main()
