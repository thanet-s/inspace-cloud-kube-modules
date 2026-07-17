#!/usr/bin/env python3
"""Crash-durable local file operations for the destructive E2E journal."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import stat
import tempfile


def _open_flags(*, directory: bool = False) -> int:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    return flags


def sync_directory(path: pathlib.Path) -> None:
    descriptor = os.open(path, _open_flags(directory=True))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def sync_file(path: pathlib.Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"durable sync requires a regular file: {path}")
    descriptor = os.open(path, _open_flags())
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    sync_directory(path.parent)


def atomic_write_bytes(path: pathlib.Path, content: bytes, mode: int = 0o600) -> None:
    path = pathlib.Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def atomic_write_text(path: pathlib.Path, content: str, mode: int = 0o600) -> None:
    atomic_write_bytes(path, content.encode("utf-8"), mode)


def atomic_write_json(path: pathlib.Path, value: object, mode: int = 0o600) -> None:
    content = json.dumps(value, indent=2, sort_keys=True) + "\n"
    atomic_write_text(path, content, mode)


def durable_remove(path: pathlib.Path) -> None:
    path = pathlib.Path(path)
    try:
        path.unlink()
    except FileNotFoundError:
        return
    sync_directory(path.parent)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)

    write_text = subparsers.add_parser("write-text")
    write_text.add_argument("path")
    write_text.add_argument("content")

    sync_file_parser = subparsers.add_parser("sync-file")
    sync_file_parser.add_argument("path")

    sync_directory_parser = subparsers.add_parser("sync-directory")
    sync_directory_parser.add_argument("path")

    remove = subparsers.add_parser("remove")
    remove.add_argument("path")

    args = parser.parse_args()
    path = pathlib.Path(args.path)
    if args.operation == "write-text":
        atomic_write_text(path, args.content)
    elif args.operation == "sync-file":
        sync_file(path)
    elif args.operation == "sync-directory":
        sync_directory(path)
    else:
        durable_remove(path)


if __name__ == "__main__":
    main()
