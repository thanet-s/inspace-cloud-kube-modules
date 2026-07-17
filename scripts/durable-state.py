#!/usr/bin/env python3
"""Crash-durable replace/remove operations for local mutation receipts."""

from __future__ import annotations

import argparse
import os
import pathlib


def sync_file(path: pathlib.Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def sync_directory(path: pathlib.Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def replace(source: pathlib.Path, destination: pathlib.Path) -> None:
    source = source.resolve(strict=True)
    destination = destination.parent.resolve(strict=True) / destination.name
    if source.parent != destination.parent:
        raise ValueError("durable replace requires source and destination in the same directory")
    sync_file(source)
    os.replace(source, destination)
    sync_directory(destination.parent)


def remove(destination: pathlib.Path) -> None:
    destination = destination.parent.resolve(strict=True) / destination.name
    try:
        os.unlink(destination)
    except FileNotFoundError:
        return
    sync_directory(destination.parent)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("replace", "remove"))
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    if args.operation == "replace":
        if len(args.paths) != 2:
            parser.error("replace requires SOURCE DESTINATION")
        replace(pathlib.Path(args.paths[0]), pathlib.Path(args.paths[1]))
        return
    if len(args.paths) != 1:
        parser.error("remove requires DESTINATION")
    remove(pathlib.Path(args.paths[0]))


if __name__ == "__main__":
    main()
