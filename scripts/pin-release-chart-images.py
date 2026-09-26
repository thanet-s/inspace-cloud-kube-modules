#!/usr/bin/env python3
"""Pin the release chart's controller images to their exact tag and index digest.

Usage: pin-release-chart-images.py <values.yaml> <image-digest-dir> <version>

The digest directory holds the release workflow's immutable image-digest
records (<image>.txt, one ``ghcr.io/<owner>/<image>@sha256:<hex>`` line each).
Every record must name the repository already configured in values.yaml, and
every image block must still carry the empty release-managed tag and digest
placeholders. The file is rewritten only after all three blocks validate.
"""

from __future__ import annotations

import os
import pathlib
import re
import sys
import tempfile


IMAGES = (
    "inspace-cloud-controller-manager",
    "inspace-csi-driver",
    "karpenter-provider-inspace",
)
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_RECORD_BYTES = 4096


class PinError(Exception):
    pass


def read_record(directory: pathlib.Path, image: str) -> tuple[str, str]:
    path = directory / f"{image}.txt"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RECORD_BYTES:
        raise PinError(f"image-digest record for {image} must be a small regular file")
    try:
        content = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as error:
        raise PinError(f"image-digest record for {image} is not UTF-8") from error
    if not content.endswith("\n") or content.count("\n") != 1:
        raise PinError(f"image-digest record for {image} must be exactly one line")
    reference = content[:-1]
    repository, separator, digest = reference.partition("@")
    if (
        separator != "@"
        or DIGEST.fullmatch(digest) is None
        or not repository.startswith("ghcr.io/")
        or not repository.endswith("/" + image)
    ):
        raise PinError(f"image-digest record for {image} is not an exact ghcr.io index digest")
    return repository, digest


def pin(values: str, records: dict[str, tuple[str, str]], version: str) -> str:
    for image in IMAGES:
        repository, digest = records[image]
        block = re.compile(
            rf'(?m)^(    repository: {re.escape(repository)}\n(?:    #[^\n]*\n)*)'
            r'    tag: ""\n    digest: ""\n'
        )
        matches = block.findall(values)
        if len(matches) != 1:
            raise PinError(
                f"values must contain exactly one unpinned {repository} block for {image}"
            )
        values = block.sub(
            lambda match: f'{match.group(1)}    tag: "{version}"\n    digest: "{digest}"\n',
            values,
            count=1,
        )
    if re.search(r'(?m)^    (?:tag|digest): ""$', values):
        raise PinError("values still contain an unpinned release-managed image field")
    return values


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(
            "usage: pin-release-chart-images.py <values.yaml> <image-digest-dir> <version>",
            file=sys.stderr,
        )
        return 2
    values_path = pathlib.Path(argv[1])
    directory = pathlib.Path(argv[2])
    version = argv[3]
    try:
        if VERSION.fullmatch(version) is None:
            raise PinError("version must be an exact SemVer without a v prefix")
        if not directory.is_dir() or directory.is_symlink():
            raise PinError("image-digest directory must be a real directory")
        present = sorted(entry.name for entry in directory.iterdir())
        if present != sorted(f"{image}.txt" for image in IMAGES):
            raise PinError(
                "image-digest directory must contain exactly the three controller records"
            )
        records = {image: read_record(directory, image) for image in IMAGES}
        original = values_path.read_bytes().decode("utf-8")
        pinned = pin(original, records, version)
    except (OSError, UnicodeDecodeError, PinError) as error:
        print(f"pin-release-chart-images: {error}", file=sys.stderr)
        return 1

    mode = values_path.stat().st_mode & 0o777
    descriptor, temporary = tempfile.mkstemp(
        prefix=".values.", suffix=".partial", dir=values_path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(pinned.encode("utf-8"))
        os.chmod(temporary, mode)
        os.replace(temporary, values_path)
    except BaseException:
        pathlib.Path(temporary).unlink(missing_ok=True)
        raise
    for image in IMAGES:
        repository, digest = records[image]
        print(f"{repository}:{version}@{digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
