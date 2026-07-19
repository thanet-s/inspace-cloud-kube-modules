#!/usr/bin/env python3
"""Black-box checks for live-suite mutation ambiguity and restart safety."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


ROOT = pathlib.Path(__file__).resolve().parents[1]
LIVE_SUITE = ROOT / "scripts" / "live-suite.sh"
LIVE_AUDIT = ROOT / "scripts" / "live-audit.sh"


class CloudState:
    def __init__(self) -> None:
        self.locations: list[dict] = [
            {"slug": "bkk01", "display_name": "Bangkok"},
            {"slug": "hkt01", "display_name": "Phuket"},
        ]
        self.firewalls: list[dict] = []
        self.create_mode = "normal"
        self.delete_mode = "normal"
        self.posts = 0
        self.deletes = 0
        self.last_created: dict | None = None
        self.created_names: list[str] = []
        self.firewall_list_status = 200
        self.receipt_path: pathlib.Path | None = None
        self.inject_exact_on_create_issue = False
        self.injected_exact = False
        self.drift_network_on_create_issue = False
        self.drift_billing_on_delete_issue = False
        self.delete_drifted = False
        self.fail_after_first_absent_delete_read = False
        self.absent_delete_reads = 0

    def receipt(self) -> dict | None:
        if self.receipt_path is None:
            return None
        try:
            return json.loads(self.receipt_path.read_text())
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None


class Handler(BaseHTTPRequestHandler):
    server: "FakeServer"

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def send_json(self, status: int, value: object) -> None:
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        state = self.server.state
        if self.path == "/v1/config/locations":
            self.send_json(200, state.locations)
        elif self.path == "/v1/bkk01/network/network/11111111-1111-4111-8111-111111111111":
            receipt = state.receipt()
            phase = receipt.get("phase") if receipt else ""
            subnet = "10.0.1.0/24" if state.drift_network_on_create_issue and phase == "create-issued" else "10.0.0.0/24"
            self.send_json(200, {"uuid": "11111111-1111-4111-8111-111111111111", "subnet": subnet})
        elif self.path == "/v1/bkk01/network/firewalls":
            receipt = state.receipt()
            phase = receipt.get("phase") if receipt else ""
            if state.inject_exact_on_create_issue and not state.injected_exact and phase == "create-issued":
                name = receipt["firewall"]["name"]
                subnet = "10.0.0.0/24"
                rules = []
                for protocol in ("tcp", "udp", "icmp"):
                    rules.extend([
                        {
                            "protocol": protocol, "direction": "inbound",
                            "port_start": None, "port_end": None,
                            "endpoint_spec_type": "ip_prefixes", "endpoint_spec": [subnet],
                        },
                        {
                            "protocol": protocol, "direction": "outbound",
                            "port_start": None, "port_end": None,
                            "endpoint_spec_type": "any", "endpoint_spec": [],
                        },
                    ])
                state.firewalls.append({
                    "uuid": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                    "display_name": name,
                    "billing_account_id": 42,
                    "resources_assigned": [],
                    "rules": rules,
                })
                state.injected_exact = True
            if state.drift_billing_on_delete_issue and not state.delete_drifted and phase == "delete-issued":
                target = receipt["firewall"]["uuid"]
                for firewall in state.firewalls:
                    if firewall["uuid"] == target:
                        firewall["billing_account_id"] = 99
                        state.delete_drifted = True
            if state.fail_after_first_absent_delete_read and phase == "delete-issued":
                target = receipt["firewall"]["uuid"]
                if all(item["uuid"] != target for item in state.firewalls):
                    state.absent_delete_reads += 1
                    if state.absent_delete_reads >= 2:
                        state.firewall_list_status = 500
            self.send_json(state.firewall_list_status, state.firewalls)
        elif self.path == "/v1/hkt01/network/firewalls":
            self.send_json(200, [])
        elif self.path in {
            f"/v1/{location}/{resource}"
            for location in ("bkk01", "hkt01")
            for resource in (
                "user-resource/vm/list",
                "storage/disks",
                "network/load_balancers",
                "network/ip_addresses",
            )
        }:
            self.send_json(200, [])
        else:
            self.send_json(404, {"message": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        state = self.server.state
        if self.path != "/v1/bkk01/network/firewalls":
            self.send_json(404, {"message": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length))
        state.posts += 1
        created = {
            "uuid": str(uuid.uuid4()),
            "display_name": request["display_name"],
            "billing_account_id": request["billing_account_id"],
            "resources_assigned": [],
            "rules": request["rules"],
        }
        state.last_created = created
        state.created_names.append(created["display_name"])
        if not state.create_mode.startswith("no-commit-"):
            state.firewalls.append(created)
        if state.create_mode.endswith("-drop"):
            self.close_connection = True
        elif state.create_mode.endswith("-500"):
            self.send_json(500, {"message": "injected ambiguous create"})
        elif state.create_mode.endswith("-409"):
            self.send_json(409, {"message": "injected ambiguous create"})
        elif state.create_mode == "foreign-response":
            response = dict(created)
            response["uuid"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
            self.send_json(201, response)
        else:
            self.send_json(201, created)

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        state = self.server.state
        prefix = "/v1/bkk01/network/firewalls/"
        if not self.path.startswith(prefix):
            self.send_json(404, {"message": "not found"})
            return
        target = self.path.removeprefix(prefix)
        state.deletes += 1
        if not state.delete_mode.startswith("no-commit-"):
            state.firewalls = [item for item in state.firewalls if item["uuid"] != target]
        if state.delete_mode.endswith("-drop"):
            self.close_connection = True
        elif state.delete_mode.endswith("-500"):
            self.send_json(500, {"message": "injected ambiguous delete"})
        elif state.delete_mode.endswith("-409"):
            self.send_json(409, {"message": "injected ambiguous delete"})
        else:
            self.send_response(204)
            self.end_headers()


class FakeServer(ThreadingHTTPServer):
    def __init__(self, state: CloudState):
        super().__init__(("127.0.0.1", 0), Handler)
        self.state = state


def suite_env(server: FakeServer, state_dir: pathlib.Path, external_firewall: bool = False) -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "INSPACE_API_URL": f"http://127.0.0.1:{server.server_port}",
            "INSPACE_API_TOKEN": "test-token",
            "INSPACE_LOCATION": "bkk01",
            "INSPACE_BILLING_ACCOUNT_ID": "42",
            "INSPACE_NETWORK_UUID": "11111111-1111-4111-8111-111111111111",
            "CONFIRM_INSPACE_LIVE_TEST": "42",
            "INSPACE_LIVE_STATE_DIR": str(state_dir),
            "INSPACE_LIVE_READBACK_ATTEMPTS": "3",
            "INSPACE_LIVE_READBACK_DELAY_SECONDS": "0",
            "INSPACE_LIVE_ABSENCE_OBSERVATIONS": "3",
            "INSPACE_LIVE_DESTRUCTIVE_ABSENCE_DELAY_SECONDS": "0",
            "INSPACE_SKIP_DOTENV": "true",
            # Default durable mode must never invoke the legacy module targets.
            "MAKE": "/usr/bin/false",
        }
    )
    if external_firewall:
        env["INSPACE_FIREWALL_UUID"] = "33333333-3333-4333-8333-333333333333"
    else:
        env.pop("INSPACE_FIREWALL_UUID", None)
    env.pop("INSPACE_ENABLE_UNJOURNALED_MODULE_LIVE_TESTS", None)
    env.pop("INSPACE_AMD_HOST_POOL_UUID", None)
    env.pop("INSPACE_TEST_HOST_POOL_UUID", None)
    env.pop("INSPACE_HOST_POOL_UUID", None)
    return env


def run_suite(server: FakeServer, state_dir: pathlib.Path, external_firewall: bool = False) -> subprocess.CompletedProcess[str]:
    server.state.receipt_path = state_dir / "firewall-mutation.json"
    return subprocess.run(
        [str(LIVE_SUITE)],
        cwd=ROOT,
        env=suite_env(server, state_dir, external_firewall),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )


def require(condition: bool, message: str, result: subprocess.CompletedProcess[str] | None = None) -> None:
    if condition:
        return
    detail = ""
    if result is not None:
        detail = f"\nexit={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    raise AssertionError(message + detail)


def audit_env(server: FakeServer) -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "INSPACE_API_URL": f"http://127.0.0.1:{server.server_port}",
            "INSPACE_API_TOKEN": "test-token",
            "INSPACE_LOCATION": "bkk01",
            "INSPACE_LIVE_RESOURCE_PREFIX": "inspace-e2e-",
            "INSPACE_SKIP_DOTENV": "true",
        }
    )
    return env


def run_audit(server: FakeServer, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(LIVE_AUDIT)],
        cwd=ROOT,
        env=env if env is not None else audit_env(server),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )


def test_remote_plaintext_api_urls_are_rejected(server: FakeServer, root: pathlib.Path) -> None:
    suite_environment = suite_env(server, root / "remote-http")
    suite_environment["INSPACE_API_URL"] = "http://api.example.invalid"
    suite = subprocess.run(
        [str(LIVE_SUITE)],
        cwd=ROOT,
        env=suite_environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    require(suite.returncode == 2, "live-suite accepted a remote plaintext API URL", suite)
    require("must use HTTPS" in suite.stderr, "live-suite plaintext rejection was not explicit", suite)

    audit_environment = audit_env(server)
    audit_environment["INSPACE_API_URL"] = "http://api.example.invalid"
    audit = run_audit(server, audit_environment)
    require(audit.returncode == 2, "live-audit accepted a remote plaintext API URL", audit)
    require("must use HTTPS" in audit.stderr, "live-audit plaintext rejection was not explicit", audit)
    require(server.state.posts == 0 and server.state.deletes == 0, "plaintext rejection crossed a mutation boundary")


def test_live_audit_validates_location_schema(server: FakeServer) -> None:
    state = server.state
    state.locations = [
        {"slug": "bkk01", "display_name": "Bangkok"},
        {"slug": "hkt01", "display_name": "Phuket"},
    ]
    state.firewalls = []
    valid = run_audit(server)
    require(valid.returncode == 0, "live-audit rejected a valid all-location inventory", valid)

    state.locations = [{"slug": 123, "display_name": "invalid"}]
    invalid = run_audit(server)
    require(invalid.returncode != 0, "live-audit accepted a non-string location slug", invalid)
    state.locations = [
        {"slug": "bkk01", "display_name": "Bangkok"},
        {"slug": "hkt01", "display_name": "Phuket"},
    ]


def test_committed_500_is_adopted_and_cleaned(server: FakeServer, root: pathlib.Path) -> None:
    state = server.state
    supplied = {
        "uuid": "33333333-3333-4333-8333-333333333333",
        "display_name": "operator-supplied-firewall",
        "billing_account_id": 42,
        "resources_assigned": [{"uuid": "55555555-5555-4555-8555-555555555555", "type": "vm"}],
        "rules": [],
    }
    state.firewalls = [supplied]
    state.create_mode = "commit-500"
    state.delete_mode = "commit-500"
    result = run_suite(server, root / "committed", external_firewall=True)
    require(result.returncode == 0, "committed HTTP 500 lifecycle must converge by exact readback", result)
    require(state.posts == 1, "committed create must dispatch exactly one POST", result)
    require(state.deletes == 1, "committed delete must dispatch exactly one DELETE", result)
    require(state.firewalls == [supplied], "conformance must never delete the operator-supplied firewall", result)
    require(not (root / "committed" / "firewall-mutation.json").exists(), "absence proof must clear receipt", result)


def test_committed_4xx_and_transport_drop_are_read_back(server: FakeServer, root: pathlib.Path) -> None:
    for mode in ("commit-409", "commit-drop"):
        state = server.state
        supplied = {
            "uuid": "33333333-3333-4333-8333-333333333333",
            "display_name": "operator-supplied-firewall",
            "billing_account_id": 42,
            "resources_assigned": [{"uuid": "55555555-5555-4555-8555-555555555555", "type": "vm"}],
            "rules": [],
        }
        state.firewalls = [supplied]
        state.posts = 0
        state.deletes = 0
        state.created_names = []
        state.create_mode = mode
        state.delete_mode = mode
        result = run_suite(server, root / mode, external_firewall=True)
        require(result.returncode == 0, f"{mode} lifecycle must converge by exact readback", result)
        require(state.posts == 1 and state.deletes == 1, f"{mode} mutations must each dispatch once", result)
        require(state.firewalls == [supplied], f"{mode} cleanup changed operator resources", result)
        require(not (root / mode / "firewall-mutation.json").exists(), f"{mode} receipt was not cleared by absence proof", result)


def test_foreign_create_response_uuid_is_never_anchored(server: FakeServer, root: pathlib.Path) -> None:
    state = server.state
    foreign = {
        "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "display_name": "operator-owned-firewall",
        "billing_account_id": 42,
        "resources_assigned": [{"uuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "type": "vm"}],
        "rules": [],
    }
    state.firewalls = [foreign]
    state.posts = 0
    state.deletes = 0
    state.created_names = []
    state.create_mode = "foreign-response"
    state.delete_mode = "normal"
    result = run_suite(server, root / "foreign-response", external_firewall=True)
    require(result.returncode == 0, "foreign response UUID must fall back to canonical name readback", result)
    require(state.posts == 1 and state.deletes == 1, "canonical create must be dispatched and cleaned exactly once", result)
    require(state.firewalls == [foreign], "foreign response UUID resource was mutated", result)
    require(
        not (root / "foreign-response" / "firewall-mutation.json").exists(),
        "canonical cleanup did not clear its durable receipt",
        result,
    )


def test_post_journal_create_adopts_exact_appearance_without_post(server: FakeServer, root: pathlib.Path) -> None:
    state = server.state
    state.firewalls = []
    state.posts = 0
    state.deletes = 0
    state.created_names = []
    state.create_mode = "normal"
    state.delete_mode = "normal"
    state.firewall_list_status = 200
    state.inject_exact_on_create_issue = True
    state.injected_exact = False
    result = run_suite(server, root / "post-journal-create")
    state.inject_exact_on_create_issue = False
    require(result.returncode == 0, "post-journal exact appearance must be adopted read-only", result)
    require(state.injected_exact, "fake API did not inject the post-journal exact firewall", result)
    require(state.posts == 0, "post-journal exact appearance still caused a duplicate POST", result)
    require(state.deletes == 1 and state.firewalls == [], "adopted exact firewall was not cleaned once", result)


def test_post_journal_network_drift_blocks_create(server: FakeServer, root: pathlib.Path) -> None:
    state = server.state
    state.firewalls = []
    state.posts = 0
    state.deletes = 0
    state.created_names = []
    state.create_mode = "normal"
    state.delete_mode = "normal"
    state.firewall_list_status = 200
    state.drift_network_on_create_issue = True
    directory = root / "post-journal-network-drift"
    result = run_suite(server, directory)
    state.drift_network_on_create_issue = False
    require(result.returncode != 0, "post-journal VPC subnet drift must fail closed", result)
    require(state.posts == 0 and state.deletes == 0, "post-journal VPC drift crossed the mutation boundary", result)
    receipt = json.loads((directory / "firewall-mutation.json").read_text())
    require(receipt["phase"] == "create-issued", "post-journal VPC drift lost its durable create receipt", result)


def test_post_journal_delete_drift_blocks_dispatch(server: FakeServer, root: pathlib.Path) -> None:
    state = server.state
    state.firewalls = []
    state.posts = 0
    state.deletes = 0
    state.created_names = []
    state.create_mode = "normal"
    state.delete_mode = "normal"
    state.firewall_list_status = 200
    state.drift_billing_on_delete_issue = True
    state.delete_drifted = False
    directory = root / "post-journal-delete-drift"
    result = run_suite(server, directory)
    state.drift_billing_on_delete_issue = False
    require(result.returncode != 0, "post-journal billing drift must fail closed", result)
    require(state.posts == 1 and state.deletes == 0, "post-journal drift crossed the mutation boundary", result)
    require(state.delete_drifted and len(state.firewalls) == 1, "fake API did not preserve the drifted firewall", result)
    receipt = json.loads((directory / "firewall-mutation.json").read_text())
    require(receipt["phase"] == "delete-issued", "post-journal drift lost its durable delete receipt", result)
    state.firewalls = []


def test_delete_absence_observation_resumes_without_replay(server: FakeServer, root: pathlib.Path) -> None:
    state = server.state
    state.firewalls = []
    state.posts = 0
    state.deletes = 0
    state.created_names = []
    state.create_mode = "normal"
    state.delete_mode = "normal"
    state.firewall_list_status = 200
    state.fail_after_first_absent_delete_read = True
    state.absent_delete_reads = 0
    directory = root / "persisted-delete-absence"
    first = run_suite(server, directory)
    require(first.returncode != 0, "injected read outage should retain delete receipt", first)
    receipt_path = directory / "firewall-mutation.json"
    receipt = json.loads(receipt_path.read_text())
    require(
        receipt["phase"] == "delete-issued" and receipt["absence"]["count"] == 1,
        "first destructive absence observation was not persisted",
        first,
    )
    require(state.posts == 1 and state.deletes == 1, "first lifecycle mutation count is incorrect", first)

    state.fail_after_first_absent_delete_read = False
    state.firewall_list_status = 200
    recovered = run_suite(server, directory, external_firewall=True)
    require(recovered.returncode == 0, "restart did not resume persisted destructive absence", recovered)
    require(state.posts == 2 and state.deletes == 2, "restart replayed the old DELETE", recovered)
    require(not receipt_path.exists(), "resumed destructive absence did not clear the receipt", recovered)


def test_uncommitted_4xx_and_transport_drop_never_replay(server: FakeServer, root: pathlib.Path) -> None:
    for mode in ("no-commit-409", "no-commit-drop"):
        state = server.state
        state.firewalls = []
        state.posts = 0
        state.deletes = 0
        state.created_names = []
        state.create_mode = mode
        state.delete_mode = "normal"
        create_directory = root / f"{mode}-create"
        first = run_suite(server, create_directory)
        second = run_suite(server, create_directory)
        require(first.returncode != 0 and second.returncode != 0, f"{mode} create must remain unresolved", second)
        require(state.posts == 1 and state.deletes == 0, f"{mode} create was replayed", second)
        receipt = json.loads((create_directory / "firewall-mutation.json").read_text())
        require(receipt["phase"] == "create-issued", f"{mode} create lost its issued receipt", second)

        state.firewalls = []
        state.posts = 0
        state.deletes = 0
        state.created_names = []
        state.create_mode = "normal"
        state.delete_mode = mode
        delete_directory = root / f"{mode}-delete"
        first = run_suite(server, delete_directory)
        second = run_suite(server, delete_directory)
        require(first.returncode != 0 and second.returncode != 0, f"{mode} delete must remain unresolved", second)
        require(state.posts == 1 and state.deletes == 1, f"{mode} delete was replayed", second)
        receipt = json.loads((delete_directory / "firewall-mutation.json").read_text())
        require(receipt["phase"] == "delete-issued", f"{mode} delete lost its issued receipt", second)


def test_failed_authoritative_read_stops_before_mutation(server: FakeServer, root: pathlib.Path) -> None:
    state = server.state
    state.firewalls = []
    state.posts = 0
    state.deletes = 0
    state.firewall_list_status = 500
    result = run_suite(server, root / "failed-read")
    state.firewall_list_status = 200
    require(result.returncode != 0, "HTTP 500 list response must fail closed", result)
    require(state.posts == 0 and state.deletes == 0, "failed authoritative read must dispatch no mutation", result)


def test_unresolved_create_never_replays(server: FakeServer, root: pathlib.Path) -> None:
    state = server.state
    state.firewalls = []
    state.posts = 0
    state.deletes = 0
    state.created_names = []
    state.create_mode = "no-commit-500"
    state.delete_mode = "commit-500"
    directory = root / "unresolved-create"
    first = run_suite(server, directory)
    require(first.returncode != 0, "unresolved create must fail closed", first)
    receipt_path = directory / "firewall-mutation.json"
    receipt = json.loads(receipt_path.read_text())
    issued_name = receipt["firewall"]["name"]
    require(receipt["phase"] == "create-issued", "unresolved create must retain issued receipt", first)
    second = run_suite(server, directory)
    require(second.returncode != 0, "restart must remain blocked while issued create is invisible", second)
    require(state.posts == 1, "restart must never replay an ambiguous POST", second)

    # Model delayed eventual visibility. The next restart may adopt only this
    # exact deterministic name, then issue one journaled cleanup DELETE.
    require(state.last_created is not None, "fake API did not retain its delayed create candidate")
    state.firewalls.append(dict(state.last_created))
    state.create_mode = "normal"
    recovered = run_suite(server, directory, external_firewall=True)
    require(recovered.returncode == 0, "late exact create must be adopted and cleaned", recovered)
    require(state.created_names.count(issued_name) == 1, "recovery must not replay the ambiguous POST", recovered)
    require(state.posts == 2, "recovery run must still execute one fresh conformance POST", recovered)
    require(state.deletes == 2, "recovery must clean both the late result and fresh conformance firewall", recovered)
    require(not receipt_path.exists(), "confirmed late cleanup must clear receipt", recovered)


def test_unresolved_delete_never_replays(server: FakeServer, root: pathlib.Path) -> None:
    state = server.state
    state.firewalls = []
    state.posts = 0
    state.deletes = 0
    state.created_names = []
    state.create_mode = "normal"
    state.delete_mode = "no-commit-500"
    directory = root / "unresolved-delete"
    first = run_suite(server, directory)
    require(first.returncode != 0, "visible resource after ambiguous delete must fail closed", first)
    receipt_path = directory / "firewall-mutation.json"
    receipt = json.loads(receipt_path.read_text())
    issued_name = receipt["firewall"]["name"]
    require(receipt["phase"] == "delete-issued", "unresolved delete must retain issued receipt", first)
    second = run_suite(server, directory)
    require(second.returncode != 0, "restart must not reissue a still-visible delete", second)
    require(state.deletes == 1, "restart must never replay an ambiguous DELETE", second)

    # Model the original deletion becoming visible later. Only repeated exact
    # absence readback is allowed to complete the receipt.
    state.firewalls = []
    state.delete_mode = "normal"
    recovered = run_suite(server, directory, external_firewall=True)
    require(recovered.returncode == 0, "late delete convergence must clear receipt", recovered)
    require(state.created_names.count(issued_name) == 1, "absence recovery must not replay the old create", recovered)
    require(state.posts == 2, "recovery must execute a fresh conformance POST", recovered)
    require(state.deletes == 2, "old DELETE must not replay; only fresh conformance cleanup may delete", recovered)
    require(not receipt_path.exists(), "confirmed absence must clear delete receipt", recovered)


def test_anchored_uuid_rename_never_clears_delete_receipt(server: FakeServer, root: pathlib.Path) -> None:
    state = server.state
    state.firewalls = []
    state.posts = 0
    state.deletes = 0
    state.created_names = []
    state.create_mode = "normal"
    state.delete_mode = "no-commit-500"
    directory = root / "anchored-uuid-rename"
    first = run_suite(server, directory)
    require(first.returncode != 0, "rename fixture must retain an unresolved exact delete", first)
    receipt_path = directory / "firewall-mutation.json"
    receipt = json.loads(receipt_path.read_text())
    require(receipt["phase"] == "delete-issued" and receipt["firewall"]["uuid"], "rename fixture lacks exact UUID receipt", first)
    require(len(state.firewalls) == 1, "rename fixture exact firewall is missing", first)

    state.firewalls[0]["display_name"] = "renamed-out-of-band"
    second = run_suite(server, directory, external_firewall=True)
    require(second.returncode != 0, "renamed exact UUID must fail closed", second)
    require(state.posts == 1 and state.deletes == 1, "renamed exact UUID triggered another mutation", second)
    require(receipt_path.exists(), "renamed exact UUID incorrectly cleared its durable receipt", second)
    retained = json.loads(receipt_path.read_text())
    require(retained == receipt, "renamed exact UUID changed its issued receipt", second)


def test_adoption_requires_exact_policy_and_no_assignments(server: FakeServer, root: pathlib.Path) -> None:
    state = server.state
    state.firewalls = []
    state.posts = 0
    state.deletes = 0
    state.created_names = []
    state.create_mode = "no-commit-500"
    state.delete_mode = "commit-500"
    directory = root / "adoption-identity"
    first = run_suite(server, directory)
    require(first.returncode != 0, "identity fixture must leave an issued create", first)
    require(state.last_created is not None, "fake API did not retain an issued create candidate")

    wrong_policy = dict(state.last_created)
    wrong_policy["rules"] = []
    state.firewalls = [wrong_policy]
    collision = run_suite(server, directory, external_firewall=True)
    require(collision.returncode != 0, "same-name wrong-policy firewall must never be adopted", collision)
    require(state.posts == 1 and state.deletes == 0, "identity collision must dispatch no mutation", collision)

    assigned = dict(state.last_created)
    assigned["resources_assigned"] = [{"uuid": "44444444-4444-4444-8444-444444444444", "type": "vm"}]
    state.firewalls = [assigned]
    occupied = run_suite(server, directory, external_firewall=True)
    require(occupied.returncode != 0, "assigned firewall must never be exported as recovered test policy", occupied)
    require(state.posts == 1 and state.deletes == 0, "assigned adoption must dispatch no mutation", occupied)

    assigned["resources_assigned"] = []
    state.create_mode = "normal"
    recovered = run_suite(server, directory, external_firewall=True)
    require(recovered.returncode == 0, "exact unassigned policy must be recoverable", recovered)
    require(state.posts == 2 and state.deletes == 2, "exact recovery must clean the old result and fresh conformance firewall", recovered)


def test_legacy_module_targets_are_retired() -> None:
    env = dict(os.environ)
    env.update(
        {
            "INSPACE_RUN_LIVE_TESTS": "true",
            "INSPACE_ALLOW_REMOTE_MUTATIONS": "true",
        }
    )
    env["INSPACE_ENABLE_UNJOURNALED_MODULE_LIVE_TESTS"] = "true"
    for module in ("cloud-provider", "csi-driver", "karpenter-provider"):
        result = subprocess.run(
            ["make", "-C", str(ROOT / "modules" / module), "live-test"],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        require(result.returncode != 0, f"{module} retired live target executed", result)
        require(
            "retired: unjournaled module live tests are unsafe" in result.stdout + result.stderr,
            f"{module} retired live target did not explain the durable replacement",
            result,
        )


def main() -> None:
    script = LIVE_SUITE.read_text(encoding="utf-8")
    require(
        "command -v sha256sum" in script and "command -v shasum" in script,
        "live-suite hash selection must support both Ubuntu sha256sum and macOS shasum",
    )
    state = CloudState()
    server = FakeServer(state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="inspace-live-suite-test-") as temporary:
            root = pathlib.Path(temporary)
            test_remote_plaintext_api_urls_are_rejected(server, root)
            test_live_audit_validates_location_schema(server)
            test_committed_500_is_adopted_and_cleaned(server, root)
            test_committed_4xx_and_transport_drop_are_read_back(server, root)
            test_foreign_create_response_uuid_is_never_anchored(server, root)
            test_post_journal_create_adopts_exact_appearance_without_post(server, root)
            test_post_journal_network_drift_blocks_create(server, root)
            test_post_journal_delete_drift_blocks_dispatch(server, root)
            test_delete_absence_observation_resumes_without_replay(server, root)
            test_uncommitted_4xx_and_transport_drop_never_replay(server, root)
            test_failed_authoritative_read_stops_before_mutation(server, root)
            test_unresolved_create_never_replays(server, root)
            test_unresolved_delete_never_replays(server, root)
            test_anchored_uuid_rename_never_clears_delete_receipt(server, root)
            test_adoption_requires_exact_policy_and_no_assignments(server, root)
            test_legacy_module_targets_are_retired()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    print("live-suite mutation ambiguity checks passed")


if __name__ == "__main__":
    main()
