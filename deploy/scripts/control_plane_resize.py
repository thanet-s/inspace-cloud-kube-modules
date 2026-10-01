#!/usr/bin/env python3
"""Decide and journal a rolling control-plane resize.

cluster.yaml keeps the init-time machine size, which the ownership hash of
every control-plane VM derives from, so it never changes. state.json records
what `update` last grew the VMs to (`controlPlaneMachine`) and, while a resize
runs, its progress (`controlPlaneResize`). This helper holds every decision
about those two keys so load-state and the resize playbook stay declarative.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import tempfile
from typing import Any

# Must equal the inventory bounds enforced by playbooks/tasks/preflight.yml.
MIN_VCPU, MAX_VCPU = 2, 16
MIN_MEMORY_MIB, MAX_MEMORY_MIB = 4096, 65536


class ResizeError(Exception):
    """A refusal the operator must resolve; the message is shown verbatim."""


Machine = tuple[int, int]


def machine_of(value: Any, label: str) -> Machine:
    if not isinstance(value, dict):
        raise ResizeError(f"{label} must be an object with vcpu and memoryMiB")
    vcpu, memory = value.get("vcpu"), value.get("memoryMiB")
    for key, number in (("vcpu", vcpu), ("memoryMiB", memory)):
        if isinstance(number, bool) or not isinstance(number, int):
            raise ResizeError(f"{label}.{key} must be a whole number")
    return vcpu, memory


def require_bounds(machine: Machine, label: str) -> None:
    vcpu, memory = machine
    if not MIN_VCPU <= vcpu <= MAX_VCPU or not MIN_MEMORY_MIB <= memory <= MAX_MEMORY_MIB:
        raise ResizeError(
            f"{label} {vcpu} vCPU / {memory} MiB is outside the supported "
            f"{MIN_VCPU}-{MAX_VCPU} vCPU and {MIN_MEMORY_MIB}-{MAX_MEMORY_MIB} MiB range"
        )


def describe(machine: Machine) -> str:
    return f"{machine[0]} vCPU / {machine[1]} MiB"


def control_plane_names(state: dict[str, Any]) -> list[str]:
    names = [item.get("name") for item in state.get("controlPlanes", [])]
    if not names or not all(isinstance(name, str) and name for name in names):
        raise ResizeError("the journal lists no valid control planes")
    return names


def has_progress(resize: dict[str, Any]) -> bool:
    return bool(resize.get("completed")) or bool(resize.get("inProgress"))


def classify(state: dict[str, Any], spec: Machine, inventory: Machine, enforce: bool = True) -> dict[str, Any]:
    """Compare the inventory size with the recorded one.

    Returns what update must do. With enforce, raises ResizeError for a
    shrink, an out-of-range size, or an inventory that contradicts a resize in
    progress. Without it (status, tunnel, destroy) the refusal is returned as
    `error` and nothing is needed, so a read-only command never blocks.
    """
    try:
        return _classify(state, spec, inventory)
    except ResizeError as error:
        if enforce:
            raise
        recorded = spec
        try:
            if "controlPlaneMachine" in state:
                recorded = machine_of(state["controlPlaneMachine"], "controlPlaneMachine")
        except ResizeError:
            pass
        return {
            "error": str(error),
            "recorded": {"vcpu": recorded[0], "memoryMiB": recorded[1]},
            "target": {"vcpu": recorded[0], "memoryMiB": recorded[1]},
            "resizeNeeded": False,
            "resuming": False,
            "staleResize": False,
            "inProgress": "",
            "pending": [],
        }


def _classify(state: dict[str, Any], spec: Machine, inventory: Machine) -> dict[str, Any]:
    if "controlPlaneMachine" in state:
        recorded = machine_of(state["controlPlaneMachine"], "controlPlaneMachine")
    else:
        recorded = spec
    names = control_plane_names(state)
    require_bounds(inventory, "inventory control_plane_vcpu / control_plane_memory_mib")

    resize = state.get("controlPlaneResize")
    completed: list[str] = []
    in_progress = ""
    resuming = False
    if resize is not None:
        if not isinstance(resize, dict):
            raise ResizeError("controlPlaneResize in the journal is malformed")
        target = machine_of(resize.get("target"), "controlPlaneResize.target")
        completed = list(resize.get("completed", []))
        in_progress = resize.get("inProgress") or ""
        unknown = [name for name in completed + ([in_progress] if in_progress else []) if name not in names]
        if unknown or len(set(completed)) != len(completed) or in_progress in completed:
            raise ResizeError("controlPlaneResize in the journal names unknown or repeated control planes")
        resuming = has_progress(resize)
        if resuming and inventory != target:
            raise ResizeError(
                f"a control-plane resize to {describe(target)} is in progress "
                f"({len(completed)} of {len(names)} servers done). Set control_plane_vcpu "
                f"and control_plane_memory_mib to {target[0]} and {target[1]} and run update "
                "again to finish it."
            )
    # A record with no started or finished server changed nothing, so the
    # inventory may re-target or drop it.
    stale = resize is not None and not resuming
    if resuming:
        needed = True
    elif inventory == recorded:
        target, needed = recorded, False
    else:
        if inventory[0] < recorded[0] or inventory[1] < recorded[1]:
            raise ResizeError(
                f"control_plane_vcpu / control_plane_memory_mib ask for {describe(inventory)} but the "
                f"control planes run {describe(recorded)}. Control planes can only grow; shrinking "
                "is not supported. Restore the recorded size, or rebuild the cluster."
            )
        target, needed = inventory, True

    return {
        "error": "",
        "recorded": {"vcpu": recorded[0], "memoryMiB": recorded[1]},
        "target": {"vcpu": target[0], "memoryMiB": target[1]},
        "resizeNeeded": needed,
        "resuming": resuming,
        "staleResize": stale,
        "inProgress": in_progress,
        "pending": [name for name in names if name not in completed] if needed else [],
    }


def begin(state: dict[str, Any], target: Machine) -> dict[str, Any]:
    control_plane_names(state)
    require_bounds(target, "target")
    recorded = machine_of(state["controlPlaneMachine"], "controlPlaneMachine") if "controlPlaneMachine" in state else None
    if recorded is not None and (target[0] < recorded[0] or target[1] < recorded[1]):
        raise ResizeError("control planes can only grow")
    existing = state.get("controlPlaneResize")
    if existing is not None:
        if machine_of(existing.get("target"), "controlPlaneResize.target") == target:
            return state
        if has_progress(existing):
            raise ResizeError("the journal already records a resize to a different size")
    state["controlPlaneResize"] = {
        "target": {"vcpu": target[0], "memoryMiB": target[1]},
        "inProgress": "",
        "completed": [],
    }
    return state


def clear(state: dict[str, Any]) -> dict[str, Any]:
    """Drop a resize record that never started a server."""
    existing = state.get("controlPlaneResize")
    if existing is None:
        return state
    if has_progress(existing):
        raise ResizeError("a resize is in progress and cannot be cleared")
    del state["controlPlaneResize"]
    return state


def resize_of(state: dict[str, Any]) -> dict[str, Any]:
    resize = state.get("controlPlaneResize")
    if not isinstance(resize, dict):
        raise ResizeError("no control-plane resize is journaled; run begin first")
    return resize


def slot_start(state: dict[str, Any], name: str) -> dict[str, Any]:
    resize = resize_of(state)
    if name not in control_plane_names(state):
        raise ResizeError(f"{name} is not a journaled control plane")
    if name in resize["completed"]:
        raise ResizeError(f"{name} already completed its resize")
    other = resize.get("inProgress") or ""
    if other and other != name:
        raise ResizeError(f"{other} is still mid-resize; finish it before starting {name}")
    resize["inProgress"] = name
    return state


def slot_done(state: dict[str, Any], name: str) -> dict[str, Any]:
    resize = resize_of(state)
    if name not in control_plane_names(state):
        raise ResizeError(f"{name} is not a journaled control plane")
    other = resize.get("inProgress") or ""
    if other and other != name:
        raise ResizeError(f"{other} is mid-resize, not {name}")
    if name not in resize["completed"]:
        resize["completed"].append(name)
    resize["inProgress"] = ""
    return state


def finish(state: dict[str, Any]) -> dict[str, Any]:
    resize = resize_of(state)
    missing = [name for name in control_plane_names(state) if name not in resize["completed"]]
    if missing or resize.get("inProgress"):
        raise ResizeError(f"the resize is not complete; still pending: {', '.join(missing) or resize['inProgress']}")
    target = machine_of(resize["target"], "controlPlaneResize.target")
    state["controlPlaneMachine"] = {"vcpu": target[0], "memoryMiB": target[1]}
    del state["controlPlaneResize"]
    return state


def atomic_write(path: pathlib.Path, value: dict[str, Any]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_state(path: pathlib.Path) -> dict[str, Any]:
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ResizeError(f"cannot read the deployment journal {path}: {error}") from error
    if not isinstance(state, dict) or state.get("schema") != "inspace-deploy-state-v1":
        raise ResizeError(f"{path} is not a deployment journal")
    return state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    classify_parser = commands.add_parser("classify", help="print what update must do for this inventory")
    classify_parser.add_argument("--state", required=True)
    classify_parser.add_argument(
        "--mode", choices=("enforce", "report"), default="enforce",
        help="report never fails, so status, tunnel and destroy ignore the size check",
    )
    classify_parser.add_argument("--spec-vcpu", required=True, type=int)
    classify_parser.add_argument("--spec-memory-mib", required=True, type=int)
    classify_parser.add_argument("--inventory-vcpu", required=True, type=int)
    classify_parser.add_argument("--inventory-memory-mib", required=True, type=int)

    for name in ("begin", "slot-start", "slot-done", "finish", "clear"):
        sub = commands.add_parser(name, help="update the journal and print the new state")
        sub.add_argument("--state", required=True)
        if name == "begin":
            sub.add_argument("--target-vcpu", required=True, type=int)
            sub.add_argument("--target-memory-mib", required=True, type=int)
        if name in ("slot-start", "slot-done"):
            sub.add_argument("--name", required=True)

    args = parser.parse_args(argv)
    try:
        path = pathlib.Path(args.state)
        state = load_state(path)
        if args.command == "classify":
            result = classify(
                state,
                (args.spec_vcpu, args.spec_memory_mib),
                (args.inventory_vcpu, args.inventory_memory_mib),
                enforce=args.mode == "enforce",
            )
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.command == "begin":
            state = begin(state, (args.target_vcpu, args.target_memory_mib))
        elif args.command == "slot-start":
            state = slot_start(state, args.name)
        elif args.command == "slot-done":
            state = slot_done(state, args.name)
        elif args.command == "clear":
            state = clear(state)
        else:
            state = finish(state)
        atomic_write(path, state)
        print(json.dumps(state, sort_keys=True))
        return 0
    except ResizeError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
