#!/usr/bin/env python3
"""Static supply-chain contracts: digest-pinned bases, digest-pinned release charts, hashed Python locks."""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCKERFILES = (
    "deploy/Dockerfile",
    "modules/cloud-provider/Dockerfile",
    "modules/csi-driver/Dockerfile",
    "modules/karpenter-provider/Dockerfile",
    "test/e2e/Dockerfile",
)
FROM_LINE = re.compile(
    r"^FROM(?:[ \t]+--platform=\S+)?[ \t]+(?P<image>\S+)(?:[ \t]+AS[ \t]+(?P<stage>\S+))?[ \t]*$",
    re.IGNORECASE,
)
# name:tag@sha256:<index digest>. The tag stays for readability and for
# Dependabot; the digest is what the builder actually resolves.
PINNED_IMAGE = re.compile(
    r"^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*"
    r":[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}@sha256:[0-9a-f]{64}$"
)
HASHED_LOCKS = {
    "deploy/requirements.lock.txt": "deploy/Dockerfile",
    "test/e2e/requirements.txt": "test/e2e/Dockerfile",
}
PINNED_REQUIREMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9.+!-]+(?:[ \t]*;[^\\]*)?[ \t]*\\?$")
HASH_LINE = re.compile(r"^[ \t]+--hash=sha256:[0-9a-f]{64}[ \t]*\\?$")


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def require(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


def discovered_dockerfiles() -> set[str]:
    found = set()
    for path in ROOT.rglob("Dockerfile*"):
        relative = path.relative_to(ROOT)
        if any(part.startswith(".") for part in relative.parts[:-1]):
            continue
        if path.name.endswith(".dockerignore") or not path.is_file():
            continue
        found.add(relative.as_posix())
    return found


def verify_dockerfile_bases() -> None:
    require(
        discovered_dockerfiles() == set(DOCKERFILES),
        "every repository Dockerfile must be listed in the base-image pin contract: "
        + ", ".join(sorted(discovered_dockerfiles() ^ set(DOCKERFILES))),
    )
    for relative in DOCKERFILES:
        stages: set[str] = set()
        from_lines = 0
        for number, line in enumerate(read(relative).splitlines(), start=1):
            if not re.match(r"^FROM[ \t]", line, re.IGNORECASE):
                continue
            from_lines += 1
            match = FROM_LINE.fullmatch(line)
            require(match is not None, f"{relative}:{number} has an unparsable FROM line")
            image = match.group("image")
            if image.lower() not in stages:
                require(
                    PINNED_IMAGE.fullmatch(image) is not None,
                    f"{relative}:{number} must pin its base image as name:tag@sha256:<index digest>, got {image}",
                )
            if match.group("stage"):
                stages.add(match.group("stage").lower())
        require(from_lines > 0, f"{relative} has no FROM line")


def verify_dependabot_covers_pinned_bases() -> None:
    dependabot = read(".github/dependabot.yml")
    for relative in DOCKERFILES:
        directory = "/" + str(pathlib.PurePosixPath(relative).parent)
        require(
            re.search(
                rf"(?m)^  - package-ecosystem: docker\n    directory: {re.escape(directory)}\n",
                dependabot,
            )
            is not None,
            f"Dependabot must watch digest-pinned base images in {directory}",
        )


def job_block(workflow: str, job: str) -> str:
    start = workflow.index(f"\n  {job}:\n")
    following = re.search(r"\n  [a-z][a-z0-9-]*:\n", workflow[start + 1 :])
    return workflow[start:] if following is None else workflow[start : start + 1 + following.start()]


def verify_release_chart_digests() -> None:
    workflow = read(".github/workflows/release.yaml")
    charts = job_block(workflow, "charts")
    require(
        re.search(r"(?m)^    needs: \[validate, quality, images\]$", charts) is not None,
        "release charts must wait for the merged, attested image digests",
    )
    require(
        "pattern: image-digest-*" in charts and "path: image-digests" in charts,
        "release charts must download the immutable image-digest records",
    )
    pin = charts.find('python3 scripts/pin-release-chart-images.py "$values_file" image-digests "$VERSION"')
    package = charts.find("helm package charts/inspace-cloud-kube-modules \\")
    require(
        0 <= pin < package,
        "release charts must inject the image-digest records into values before packaging",
    )
    require(
        re.search(r'(?m)^\s+sed -i "s/\^    tag: ', charts) is None,
        "chart image tags and digests must be pinned together by the checked release script",
    )
    readback_fragments = (
        'helm show values "dist/inspace-cloud-kube-modules-$VERSION.tgz"',
        'helm template release-readback "dist/inspace-cloud-kube-modules-$VERSION.tgz"',
        "packaged chart does not pin every controller image to its release digest",
        "packaged chart does not render every controller image by its release digest",
    )
    for fragment in readback_fragments:
        require(fragment in charts, f"release charts must read back pinned digests: {fragment}")
    # The published chart pins image-index digests. The bastion bootstrap cache
    # holds only each image's linux/amd64 manifest, so every installer that can
    # route pulls through it must override the digests with platform digests.
    e2e_init = read("test/e2e/init-cluster.yml")
    deploy_values = read("deploy/templates/chart-values.yaml.j2")
    for key, image in (
        ("ccm", "inspace-cloud-controller-manager"),
        ("csi", "inspace-csi-driver"),
        ("karpenter", "karpenter-provider-inspace"),
    ):
        require(
            f"- \"{key}.image.digest={{{{ e2e_install_release_images.images['{image}'].platformDigest }}}}\""
            in e2e_init,
            f"E2E chart install must pin {key} to the cache-compatible linux/amd64 digest",
        )
        require(
            f"deploy_modules_release_images['{image}'].platformDigest" in deploy_values,
            f"deploy chart values must pin {key} to the cache-compatible linux/amd64 digest",
        )
    require(
        (ROOT / "scripts/pin-release-chart-images.py").is_file()
        and (ROOT / "scripts/test-pin-release-chart-images.py").is_file(),
        "release chart digest pinning must be a tested repository script",
    )
    ci = read(".github/workflows/ci.yaml")
    for command in (
        "python3 scripts/test-pin-release-chart-images.py",
        "python3 scripts/verify-supply-chain-pins.py",
    ):
        require(command in ci, f"CI must run {command}")


def verify_hashed_python_locks() -> None:
    for relative, dockerfile in HASHED_LOCKS.items():
        lines = [
            line
            for line in read(relative).splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        requirements = 0
        hashes_for_current = 0
        continued = False
        for line in lines:
            if HASH_LINE.fullmatch(line):
                require(continued, f"{relative} has a --hash line outside a requirement")
                hashes_for_current += 1
                continued = line.rstrip().endswith("\\")
                continue
            require(
                not continued,
                f"{relative} continues a requirement into a non-hash line: {line.strip()}",
            )
            require(
                requirements == 0 or hashes_for_current > 0,
                f"{relative} has a requirement without a sha256 hash",
            )
            require(
                PINNED_REQUIREMENT.fullmatch(line) is not None and line.rstrip().endswith("\\"),
                f"{relative} must pin every requirement as name==version with --hash lines: {line.strip()}",
            )
            requirements += 1
            hashes_for_current = 0
            continued = True
        require(
            requirements > 0 and hashes_for_current > 0 and not continued,
            f"{relative} must end with a complete hashed requirement",
        )
        require(
            "--require-hashes" in read(dockerfile) and relative.rsplit("/", 1)[-1] in read(dockerfile),
            f"{dockerfile} must install {relative} with --require-hashes",
        )


def main() -> None:
    verify_dockerfile_bases()
    verify_dependabot_covers_pinned_bases()
    verify_release_chart_digests()
    verify_hashed_python_locks()
    print("supply-chain pin contracts: ok")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as error:
        print(f"supply-chain pin verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
