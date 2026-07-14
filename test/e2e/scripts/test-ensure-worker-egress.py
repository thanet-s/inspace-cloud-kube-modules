#!/usr/bin/env python3
"""Hermetic runtime smoke tests for the worker egress replacement gate."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap


ROOT = pathlib.Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "ensure-worker-egress.sh"
PROBE = ROOT / "templates" / "registry-egress-probe.yaml.j2"


FAKE_KUBECTL = r'''#!/usr/bin/env python3
import json
import os
import pathlib
import re
import sys


scenario = os.environ["FAKE_KUBECTL_SCENARIO"]
state_path = pathlib.Path(os.environ["FAKE_KUBECTL_STATE"])
events_path = pathlib.Path(os.environ["FAKE_KUBECTL_EVENTS"])


def fail(message):
    print(f"fake kubectl: {message}", file=sys.stderr)
    raise SystemExit(1)


def event(message):
    with events_path.open("a", encoding="utf-8") as stream:
        stream.write(message + "\n")


def node(name, public_ip):
    return {
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": {
            "name": name,
            "labels": {"karpenter.sh/nodepool": "general"},
        },
        "status": {
            "addresses": [
                {"type": "InternalIP", "address": "10.91.72.249"},
                {"type": "ExternalIP", "address": public_ip},
            ],
            "conditions": [{"type": "Ready", "status": "True"}],
        },
    }


def claim(name, node_name, public_ip):
    return {
        "apiVersion": "karpenter.sh/v1",
        "kind": "NodeClaim",
        "metadata": {
            "name": name,
            "labels": {"karpenter.sh/nodepool": "general"},
            "annotations": {
                "karpenter.inspace.cloud/public-ipv4": public_ip,
                "karpenter.inspace.cloud/floating-ip-name": f"{name}-fip",
                "karpenter.inspace.cloud/billing-account-id": "42",
            },
        },
        "status": {
            "nodeName": node_name,
            "conditions": [{"type": "Ready", "status": "True"}],
        },
    }


def initial_state():
    if scenario == "success":
        nodes = {"node-good": node("node-good", "203.0.113.20")}
        claims = {"claim-good": claim("claim-good", "node-good", "203.0.113.20")}
    elif scenario == "rotate":
        nodes = {"node-bad": node("node-bad", "199.21.172.179")}
        claims = {"claim-bad": claim("claim-bad", "node-bad", "199.21.172.179")}
    else:
        fail(f"unknown scenario {scenario}")
    return {
        "limits": {"cpu": "2", "memory": "4Gi"},
        "nodes": nodes,
        "claims": claims,
        "pods": {},
        "ready_passed": [],
        "trigger_replicas": 1,
    }


if state_path.exists():
    state = json.loads(state_path.read_text(encoding="utf-8"))
else:
    state = initial_state()


def save():
    state_path.write_text(json.dumps(state), encoding="utf-8")


def option(args, name, default=None):
    try:
        return args[args.index(name) + 1]
    except (ValueError, IndexError):
        prefix = name + "="
        return next((value[len(prefix):] for value in args if value.startswith(prefix)), default)


def pod_json(name):
    pod = state["pods"].get(name)
    if pod is None:
        fail(f"pod {name} does not exist")
    status = {"conditions": []}
    if name in state["ready_passed"]:
        status["conditions"] = [{"type": "Ready", "status": "True"}]
    elif scenario == "rotate" and name.endswith("-1"):
        status["initContainerStatuses"] = [{
            "name": "docker-hub",
            "state": {"waiting": {
                "reason": "ErrImagePull",
                "message": "dial tcp 198.51.100.10:443: i/o timeout",
            }},
        }]
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "labels": {
                "app": "inspace-e2e-egress-probe",
                "inspace.cloud/e2e-egress-gate": "true",
            },
        },
        "spec": {"nodeName": pod["node"]},
        "status": status,
    }


raw = sys.argv[1:]
args = []
index = 0
while index < len(raw):
    if raw[index] in ("--kubeconfig", "-n", "--namespace"):
        index += 2
    else:
        args.append(raw[index])
        index += 1
if not args:
    fail("missing command")

verb = args[0]

if verb == "create":
    manifest = pathlib.Path(option(args, "-f")).read_text(encoding="utf-8")
    match = re.search(r"(?m)^  name: (inspace-e2e-egress-probe-[1-3])$", manifest)
    if match is None:
        fail("probe manifest has no concrete attempt name")
    name = match.group(1)
    attempt = int(name.rsplit("-", 1)[1])
    if scenario == "success":
        assigned_node = "node-good"
    elif attempt == 1:
        assigned_node = "node-bad"
    else:
        if state["limits"] != {"cpu": "6", "memory": "12Gi"}:
            fail("replacement was requested before the NodePool overlap limit was active")
        if "claim-bad" not in state["claims"]:
            fail("bad NodeClaim/FIP was deleted before replacement allocation")
        state["nodes"]["node-good"] = node("node-good", "203.0.113.21")
        state["claims"]["claim-good"] = claim(
            "claim-good", "node-good", "203.0.113.21"
        )
        assigned_node = "node-good"
    state["pods"][name] = {"node": assigned_node}
    event(f"create:{name}:{assigned_node}")
    save()
    raise SystemExit(0)

if verb == "wait":
    resource = next((value for value in args if value.startswith("pod/")), None)
    if resource is None:
        fail("wait only supports pods")
    name = resource.split("/", 1)[1]
    if "condition=PodScheduled" in " ".join(args):
        event(f"scheduled:{name}")
        raise SystemExit(0)
    if "condition=Ready" not in " ".join(args):
        fail("unknown wait condition")
    if scenario == "rotate" and name.endswith("-1"):
        event(f"ready-timeout:{name}")
        raise SystemExit(1)
    if scenario == "rotate" and name.endswith("-2"):
        if "claim-bad" not in state["claims"]:
            fail("bad FIP was released before the replacement passed its blob pulls")
        if state["claims"]["claim-bad"]["metadata"]["annotations"][
            "karpenter.inspace.cloud/public-ipv4"
        ] != "199.21.172.179":
            fail("retained bad FIP identity changed during overlap")
    state["ready_passed"].append(name)
    event(f"ready-pass:{name}")
    save()
    raise SystemExit(0)

if verb == "get":
    resource = args[1]
    name = args[2] if len(args) > 2 and not args[2].startswith("-") else None
    selector = option(args, "-l", "")
    output = option(args, "-o", "")
    if resource == "nodepool":
        print(json.dumps({"spec": {"limits": state["limits"]}}))
    elif resource == "nodes":
        print(json.dumps({"items": list(state["nodes"].values())}))
    elif resource == "nodeclaims":
        print(json.dumps({"items": list(state["claims"].values())}))
    elif resource == "node":
        item = state["nodes"].get(name)
        if item is None:
            raise SystemExit(1)
        print(json.dumps(item))
    elif resource == "nodeclaim":
        item = state["claims"].get(name)
        if item is None:
            raise SystemExit(1)
        print(json.dumps(item))
    elif resource == "pod":
        item = pod_json(name)
        if output.startswith("jsonpath="):
            print(item["spec"]["nodeName"], end="")
        else:
            print(json.dumps(item))
    elif resource == "pods" and selector == "app=inspace-e2e-trigger":
        items = []
        if state["trigger_replicas"] == 1:
            winner = "node-good" if "node-good" in state["nodes"] else "node-bad"
            items = [{
                "spec": {"nodeName": winner},
                "status": {"conditions": [{"type": "Ready", "status": "True"}]},
            }]
        print(json.dumps({"items": items}))
    elif resource == "pods":
        items = [pod_json(pod_name) for pod_name in state["pods"]]
        print(json.dumps({"items": items}))
    elif resource == "events":
        print(json.dumps({"items": []}))
    else:
        fail(f"unsupported get: {' '.join(args)}")
    raise SystemExit(0)

if verb == "patch":
    patch = json.loads(option(args, "-p"))
    limits = patch["spec"]["limits"]
    if scenario == "rotate" and limits == {"cpu": "2", "memory": "4Gi"}:
        if "claim-bad" in state["claims"]:
            fail("NodePool limit restored before rejected NodeClaim/FIP cleanup")
        if "inspace-e2e-egress-probe-2" not in state["ready_passed"]:
            fail("NodePool limit restored before replacement registry success")
    state["limits"] = limits
    event(f"patch-limits:{limits['cpu']}:{limits['memory']}")
    save()
    raise SystemExit(0)

if verb == "scale":
    replicas = int(option(args, "--replicas"))
    if scenario == "rotate" and replicas == 0:
        if "claim-bad" not in state["claims"]:
            fail("old FIP disappeared before the winner held capacity")
        if "inspace-e2e-egress-probe-2" not in state["ready_passed"]:
            fail("normal capacity was detached before the winner passed")
    state["trigger_replicas"] = replicas
    event(f"scale-trigger:{replicas}")
    save()
    raise SystemExit(0)

if verb == "rollout":
    raise SystemExit(0)

if verb in ("label", "cordon", "uncordon"):
    event(f"{verb}:{args[2] if verb == 'label' else args[1]}")
    raise SystemExit(0)

if verb == "delete":
    resource = args[1]
    name = args[2] if len(args) > 2 and not args[2].startswith("-") else None
    selector = option(args, "-l")
    if resource == "nodeclaim":
        if name == "claim-bad":
            if "inspace-e2e-egress-probe-2" not in state["ready_passed"]:
                fail("rejected NodeClaim/FIP deleted before replacement success")
            if "claim-good" not in state["claims"]:
                fail("rejected NodeClaim/FIP deleted before replacement allocation")
        item = state["claims"].pop(name, None)
        if item is None:
            fail(f"cannot delete absent NodeClaim {name}")
        state["nodes"].pop(item["status"]["nodeName"], None)
        event(f"delete-nodeclaim:{name}")
    elif resource == "pod" and selector:
        state["pods"].clear()
        event("delete-probes")
    elif resource == "pod":
        state["pods"].pop(name, None)
        event(f"delete-pod:{name}")
    else:
        fail(f"unsupported delete: {' '.join(args)}")
    save()
    raise SystemExit(0)

fail(f"unsupported command: {' '.join(args)}")
'''


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def event_offset(events: list[str], expected: str) -> int:
    require(expected in events, f"fake kubectl did not observe {expected!r}: {events}")
    return events.index(expected)


def run_case(scenario: str) -> tuple[dict, list[str]]:
    with tempfile.TemporaryDirectory(prefix=f"inspace-egress-{scenario}-") as temporary:
        root = pathlib.Path(temporary)
        bin_dir = root / "bin"
        bin_dir.mkdir(mode=0o700)
        kubectl = bin_dir / "kubectl"
        kubectl.write_text(FAKE_KUBECTL, encoding="utf-8")
        kubectl.chmod(0o700)
        kubeconfig = root / "kubeconfig"
        kubeconfig.write_text("fake\n", encoding="utf-8")
        result_path = root / "result.json"
        events_path = root / "events.log"
        env = os.environ.copy()
        env.update({
            "PATH": f"{bin_dir}{os.pathsep}{env['PATH']}",
            "FAKE_KUBECTL_SCENARIO": scenario,
            "FAKE_KUBECTL_STATE": str(root / "state.json"),
            "FAKE_KUBECTL_EVENTS": str(events_path),
        })
        result = subprocess.run(
            [
                "/bin/bash",
                str(GATE),
                "--kubeconfig", str(kubeconfig),
                "--nodepool", "general",
                "--probe-template", str(PROBE),
                "--result", str(result_path),
            ],
            capture_output=True,
            text=True,
            check=False,
            env=env,
            timeout=30,
        )
        require(
            result.returncode == 0,
            textwrap.dedent(
                f"""\
                {scenario} gate smoke test failed with {result.returncode}
                stdout:\n{result.stdout}
                stderr:\n{result.stderr}
                """
            ),
        )
        require(
            result_path.is_file(),
            f"{scenario} gate did not write its result\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        payload = json.loads(result_path.read_text(encoding="utf-8"))
        events = events_path.read_text(encoding="utf-8").splitlines()
        return payload, events


def main() -> None:
    success, success_events = run_case("success")
    require(success["attempts"] == 1, "first-attempt success reported the wrong count")
    require(success["winner"] == {
        "node": "node-good",
        "nodeClaim": "claim-good",
        "publicIPv4": "203.0.113.20",
    }, "first-attempt success did not preserve the initial worker identity")
    require(success["rejected"] == [], "first-attempt success unexpectedly rejected a worker")
    require(not any(item.startswith("delete-nodeclaim:") for item in success_events),
            "first-attempt success deleted a NodeClaim")
    require("patch-limits:6:12Gi" not in success_events,
            "first-attempt success unnecessarily enabled overlap capacity")

    rotated, events = run_case("rotate")
    require(rotated["attempts"] == 2, "one timeout and one success must report two attempts")
    require(rotated["winner"] == {
        "node": "node-good",
        "nodeClaim": "claim-good",
        "publicIPv4": "203.0.113.21",
    }, "rotation did not select the distinct replacement FIP")
    require(rotated["rejected"] == [{
        "node": "node-bad",
        "nodeClaim": "claim-bad",
        "publicIPv4": "199.21.172.179",
    }], "rotation did not report the retained-then-deleted bad FIP")

    ordering = [
        "ready-timeout:inspace-e2e-egress-probe-1",
        "patch-limits:6:12Gi",
        "create:inspace-e2e-egress-probe-2:node-good",
        "ready-pass:inspace-e2e-egress-probe-2",
        "scale-trigger:0",
        "delete-nodeclaim:claim-bad",
        "patch-limits:2:4Gi",
    ]
    offsets = [event_offset(events, expected) for expected in ordering]
    require(offsets == sorted(offsets),
            f"replacement did not preserve overlap-before-delete ordering: {events}")
    print("worker egress gate runtime smoke verified (success and retained-FIP rotation)")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(f"worker egress gate smoke failed: {error}", file=sys.stderr)
        raise SystemExit(1)
