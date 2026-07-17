#!/usr/bin/env python3
"""Adversarial local tests for the destructive E2E InSpace read boundary."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import pathlib
import tempfile
import threading
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from strict_inspace_api import StrictAPIError, StrictInSpaceAPI


ROOT = pathlib.Path(__file__).resolve().parent


class Handler(BaseHTTPRequestHandler):
    routes: dict[str, tuple[int, dict[str, str], bytes]] = {}
    requests: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        self.requests.append(self.path)
        status, headers, body = self.routes.get(
            self.path,
            (404, {}, b'{"error":"missing test route"}'),
        )
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        if "Content-Length" not in headers:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        self.close_connection = True

    def log_message(self, _format: str, *_args: object) -> None:
        return


class LocalAPI:
    def __enter__(self):
        Handler.routes = {}
        Handler.requests = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.root = f"http://{host}:{port}"
        return self

    def __exit__(self, *_args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def client(self, token: str = "unit-test-secret") -> StrictInSpaceAPI:
        return StrictInSpaceAPI(
            base_url=self.root,
            token=token,
            user_agent="strict-api-unit-test/1",
            allow_loopback_for_tests=True,
        )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def reject(call, description: str, *, secret: str | None = None) -> None:
    try:
        call()
    except StrictAPIError as error:
        if secret is not None:
            require(secret not in str(error), f"{description} leaked the API token")
        return
    raise AssertionError(f"{description} was accepted")


def load_script(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_transport_and_json_boundary() -> None:
    reject(
        lambda: StrictInSpaceAPI(
            base_url="https://api.inspace.cloud.example",
            token="secret",
            user_agent="test/1",
        ),
        "non-canonical destructive API origin",
    )
    reject(
        lambda: StrictInSpaceAPI(
            base_url="https://api.inspace.cloud/",
            token="secret",
            user_agent="test/1",
        ),
        "non-exact destructive API root",
    )
    with LocalAPI() as api:
        path = "/v1/config/locations"
        valid = json.dumps([{"slug": "bkk01"}]).encode()
        api.Handler = Handler

        Handler.routes[path] = (200, {}, valid)
        require(
            api.client().get("config/locations", location=None)
            == [{"slug": "bkk01"}],
            "strict success response was not returned",
        )

        proxy_handler = api.client()._proxy_handler  # noqa: SLF001
        require(
            isinstance(proxy_handler, urllib.request.ProxyHandler)
            and proxy_handler.proxies == {},
            "strict reader did not install an explicit empty proxy map",
        )

        same_origin = f"{api.root}{path}?redirected=true"
        Handler.routes[path] = (302, {"Location": same_origin}, b"")
        reject(
            lambda: api.client().get("config/locations", location=None),
            "same-origin redirect",
        )
        Handler.routes[path] = (
            307,
            {"Location": "https://example.invalid/stolen"},
            b"",
        )
        reject(
            lambda: api.client().get("config/locations", location=None),
            "cross-origin redirect",
        )

        Handler.routes[path] = (206, {}, valid)
        reject(
            lambda: api.client().get("config/locations", location=None),
            "partial-content response",
        )
        for label, body in (
            ("empty body", b""),
            ("JSON null", b"null"),
            ("empty object", b"{}"),
            ("trailing JSON", b'[{"slug":"bkk01"}] trailing'),
            ("duplicate JSON key", b'[{"slug":"bkk01","slug":"hkt01"}]'),
            ("malformed JSON", b"["),
            ("omitted required field", b'[{"unknown":"bkk01"}]'),
            ("duplicate identity", b'[{"slug":"bkk01"},{"slug":"bkk01"}]'),
        ):
            Handler.routes[path] = (200, {}, body)
            reject(
                lambda: api.client().get("config/locations", location=None),
                label,
            )

        Handler.routes[path] = (
            200,
            {"Content-Length": str(len(valid) + 20)},
            valid,
        )
        reject(
            lambda: api.client().get("config/locations", location=None),
            "truncated Content-Length response",
        )
        oversized = b"[" + (b" " * (4 * 1024 * 1024)) + b"]"
        Handler.routes[path] = (200, {}, oversized)
        reject(
            lambda: api.client().get("config/locations", location=None),
            "response beyond the 4-MiB limit",
        )

        Handler.routes[path] = (500, {}, b"unit-test-secret")
        reject(
            lambda: api.client("unit-test-secret").get(
                "config/locations", location=None
            ),
            "server error body",
            secret="unit-test-secret",
        )


def test_proxy_bypass_and_exact_absence() -> None:
    old_proxy = {
        name: os.environ.get(name)
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
    }
    os.environ.update(
        {
            "HTTP_PROXY": "http://127.0.0.1:1",
            "HTTPS_PROXY": "http://127.0.0.1:1",
            "ALL_PROXY": "http://127.0.0.1:1",
            "NO_PROXY": "",
        }
    )
    try:
        with LocalAPI() as api:
            path = "/v1/config/locations"
            Handler.routes[path] = (200, {}, b'[{"slug":"bkk01"}]')
            require(
                api.client().get("config/locations", location=None)[0]["slug"]
                == "bkk01",
                "ambient proxy settings intercepted the strict reader",
            )

            address = "203.0.113.10"
            exact_path = f"/v1/bkk01/network/ip_addresses/{address}"
            Handler.routes[exact_path] = (404, {}, b'{"error":"not found"}')
            require(
                api.client().exact_absent(
                    f"network/ip_addresses/{address}", location="bkk01"
                ),
                "exact 404 was not recognized as absence",
            )
            Handler.routes[exact_path] = (
                200,
                {},
                json.dumps({"address": address}).encode(),
            )
            require(
                not api.client().exact_absent(
                    f"network/ip_addresses/{address}", location="bkk01"
                ),
                "present exact object was mistaken for absence",
            )

            vm_uuid = "11111111-1111-4111-8111-11111111111a"
            vm_route = f"/v1/bkk01/user-resource/vm?uuid={vm_uuid}"
            Handler.routes[vm_route] = (
                400,
                {},
                json.dumps(
                    {
                        "error": "No such virtual machine exists: "
                        + vm_uuid.upper()
                    }
                ).encode(),
            )
            require(
                api.client().exact_absent(
                    f"user-resource/vm?uuid={vm_uuid}", location="bkk01"
                ),
                "bound exact VM HTTP 400 was not recognized as absence",
            )
            Handler.routes[vm_route] = (
                400,
                {},
                json.dumps(
                    {
                        "errors": {
                            "Error": "No such virtual machine exists: "
                            + vm_uuid
                        }
                    }
                ).encode(),
            )
            require(
                api.client().exact_absent(
                    f"user-resource/vm?uuid={vm_uuid}", location="bkk01"
                ),
                "nested UUID-bound exact VM HTTP 400 was not recognized as absence",
            )
            Handler.routes[vm_route] = (
                400,
                {},
                b'{"error":"No such virtual machine exists: '
                b'22222222-2222-4222-8222-222222222222"}',
            )
            reject(
                lambda: api.client().exact_absent(
                    f"user-resource/vm?uuid={vm_uuid}", location="bkk01"
                ),
                "HTTP 400 for a different VM identity",
            )
            for label, body in (
                (
                    "nested HTTP 400 for a different VM identity",
                    {
                        "errors": {
                            "Error": "No such virtual machine exists: "
                            "22222222-2222-4222-8222-222222222222"
                        }
                    },
                ),
                (
                    "nested HTTP 400 without an exact VM identity",
                    {"errors": {"Error": "No such virtual machine exists"}},
                ),
                (
                    "nested HTTP 400 with an extra top-level field",
                    {
                        "errors": {
                            "Error": "No such virtual machine exists: "
                            + vm_uuid
                        },
                        "status": 400,
                    },
                ),
                (
                    "nested HTTP 400 with an extra error field",
                    {
                        "errors": {
                            "Error": "No such virtual machine exists: "
                            + vm_uuid,
                            "Code": "missing",
                        }
                    },
                ),
                (
                    "nested HTTP 400 with the wrong error-key case",
                    {
                        "errors": {
                            "error": "No such virtual machine exists: "
                            + vm_uuid
                        }
                    },
                ),
                (
                    "nested HTTP 400 with a non-object errors field",
                    {
                        "errors": "No such virtual machine exists: "
                        + vm_uuid
                    },
                ),
                (
                    "nested HTTP 400 with a non-string Error field",
                    {"errors": {"Error": {"message": vm_uuid}}},
                ),
                (
                    "nested HTTP 400 with alternate phrase casing",
                    {
                        "errors": {
                            "Error": "no such virtual machine exists: "
                            + vm_uuid
                        }
                    },
                ),
                (
                    "nested HTTP 400 with the abbreviated phrase",
                    {
                        "errors": {
                            "Error": "No such VM exists: " + vm_uuid
                        }
                    },
                ),
                (
                    "nested HTTP 400 with a period separator",
                    {
                        "errors": {
                            "Error": "No such virtual machine exists. "
                            + vm_uuid
                        }
                    },
                ),
                (
                    "nested HTTP 400 with a non-canonical UUID",
                    {
                        "errors": {
                            "Error": "No such virtual machine exists: "
                            + vm_uuid.upper()
                        }
                    },
                ),
                (
                    "nested HTTP 400 with trailing prose",
                    {
                        "errors": {
                            "Error": "No such virtual machine exists: "
                            + vm_uuid
                            + " in this account"
                        }
                    },
                ),
                (
                    "nested HTTP 400 with a matching legacy sibling",
                    {
                        "errors": {"Error": "validation failed"},
                        "error": "No such virtual machine exists: "
                        + vm_uuid,
                    },
                ),
                (
                    "case-confusable nested HTTP 400 with a legacy sibling",
                    {
                        "Errors": {"Error": "validation failed"},
                        "error": "No such virtual machine exists: "
                        + vm_uuid,
                    },
                ),
                (
                    "legacy HTTP 400 with an extra field",
                    {
                        "status": 400,
                        "error": "No such virtual machine exists: "
                        + vm_uuid,
                    },
                ),
                (
                    "legacy HTTP 400 with two message fields",
                    {
                        "message": "No such virtual machine exists: "
                        + vm_uuid,
                        "error": "No such virtual machine exists: "
                        + vm_uuid,
                    },
                ),
            ):
                Handler.routes[vm_route] = (
                    400,
                    {},
                    json.dumps(body).encode(),
                )
                reject(
                    lambda: api.client().exact_absent(
                        f"user-resource/vm?uuid={vm_uuid}",
                        location="bkk01",
                    ),
                    label,
                )
            for label, body in (
                (
                    "nested HTTP 400 with a duplicate top-level key",
                    b'{"errors":{"Error":"No such virtual machine exists: '
                    + vm_uuid.encode()
                    + b'"},"errors":{"Error":"No such virtual machine exists: '
                    + vm_uuid.encode()
                    + b'"}}',
                ),
                (
                    "nested HTTP 400 with a duplicate error key",
                    b'{"errors":{"Error":"No such virtual machine exists: '
                    + vm_uuid.encode()
                    + b'","Error":"No such virtual machine exists: '
                    + vm_uuid.encode()
                    + b'"}}',
                ),
            ):
                Handler.routes[vm_route] = (400, {}, body)
                reject(
                    lambda: api.client().exact_absent(
                        f"user-resource/vm?uuid={vm_uuid}",
                        location="bkk01",
                    ),
                    label,
                )

            disk_uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
            disk_route = f"/v1/bkk01/storage/disks/{disk_uuid}"
            deleted_disk = {
                "uuid": disk_uuid,
                "user_id": 7,
                "billing_account_id": 8,
                "status": "Deleted",
                "size_gb": 1,
                "source_image_type": "EMPTY",
                "created_at": "2026-07-17T10:00:00Z",
                "updated_at": "2026-07-17T10:02:00Z",
                "deleted_at": "2026-07-17T10:01:00Z",
                "display_name": "pvc-unit-test",
                "read_only_bootable": False,
                "snapshots": [],
                "storage_pool_uuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            }
            disk_tombstone_identity = {
                "expected_billing_account_id": 8,
                "expected_name": "pvc-unit-test",
            }
            Handler.routes[disk_route] = (
                200,
                {},
                json.dumps(deleted_disk).encode(),
            )
            require(
                api.client().exact_absent(
                    f"storage/disks/{disk_uuid}",
                    location="bkk01",
                    **disk_tombstone_identity,
                ),
                "canonical exact deleted-disk tombstone was not absence",
            )
            for label, expected_identity in (
                (
                    "wrong expected billing account",
                    {
                        **disk_tombstone_identity,
                        "expected_billing_account_id": 9,
                    },
                ),
                (
                    "wrong expected deterministic name",
                    {
                        **disk_tombstone_identity,
                        "expected_name": "pvc-other",
                    },
                ),
            ):
                reject(
                    lambda: api.client().exact_absent(
                        f"storage/disks/{disk_uuid}",
                        location="bkk01",
                        **expected_identity,
                    ),
                    f"deleted disk tombstone with {label}",
                )
            Handler.routes[disk_route] = (
                200,
                {},
                json.dumps({**deleted_disk, "status": "Active"}).encode(),
            )
            require(
                not api.client().exact_absent(
                    f"storage/disks/{disk_uuid}", location="bkk01"
                ),
                "active exact disk was mistaken for absence",
            )
            malformed_deleted_disks = {
                "wrong UUID": {
                    **deleted_disk,
                    "uuid": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                },
                "missing billing": {
                    key: value
                    for key, value in deleted_disk.items()
                    if key != "billing_account_id"
                },
                "zero billing": {
                    **deleted_disk,
                    "billing_account_id": 0,
                },
                "missing deletion time": {
                    key: value
                    for key, value in deleted_disk.items()
                    if key != "deleted_at"
                },
                "wrong source type": {
                    **deleted_disk,
                    "source_image_type": "OS_BASE",
                },
                "residual source image": {
                    **deleted_disk,
                    "source_image": "ubuntu-24.04",
                },
                "missing deterministic name": {
                    key: value
                    for key, value in deleted_disk.items()
                    if key != "display_name"
                },
                "bootable": {
                    **deleted_disk,
                    "read_only_bootable": True,
                },
                "malformed snapshots": {
                    **deleted_disk,
                    "snapshots": [1],
                },
                "malformed storage pool": {
                    **deleted_disk,
                    "storage_pool_uuid": "not-a-uuid",
                },
                "case-confusable status": {
                    **deleted_disk,
                    "Status": "Active",
                },
                "case-confusable billing": {
                    **deleted_disk,
                    "Billing_Account_ID": 9,
                },
                "case-confusable name": {
                    **deleted_disk,
                    "Display_Name": "pvc-other",
                },
            }
            for label, value in malformed_deleted_disks.items():
                Handler.routes[disk_route] = (
                    200,
                    {},
                    json.dumps(value).encode(),
                )
                reject(
                    lambda: api.client().exact_absent(
                        f"storage/disks/{disk_uuid}",
                        location="bkk01",
                        **disk_tombstone_identity,
                    ),
                    f"deleted disk tombstone with {label}",
                )
            Handler.routes[disk_route] = (
                200,
                {},
                json.dumps({**deleted_disk, "status": "deleted"}).encode(),
            )
            require(
                not api.client().exact_absent(
                    f"storage/disks/{disk_uuid}", location="bkk01"
                ),
                "noncanonical deleted-disk status was mistaken for absence",
            )

            load_balancer_uuid = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
            load_balancer_route = (
                f"/v1/bkk01/network/load_balancers/{load_balancer_uuid}"
            )
            deleted_load_balancer = {
                "uuid": load_balancer_uuid,
                "display_name": "k8s-unit-test",
                "user_id": 7,
                "billing_account_id": 8,
                "created_at": "2026-07-17T10:00:00Z",
                "updated_at": "2026-07-17T10:02:00Z",
                "is_deleted": True,
                "deleted_at": "2026-07-17T10:01:00Z",
                "private_address": "10.0.0.10",
                "network_uuid": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                "forwarding_rules": [{"protocol": "TCP"}],
                "targets": [],
            }
            load_balancer_tombstone_identity = {
                "expected_billing_account_id": 8,
                "expected_name": "k8s-unit-test",
                "expected_network_uuid": (
                    "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
                ),
            }
            Handler.routes[load_balancer_route] = (
                200,
                {},
                json.dumps(deleted_load_balancer).encode(),
            )
            require(
                api.client().exact_absent(
                    f"network/load_balancers/{load_balancer_uuid}",
                    location="bkk01",
                    **load_balancer_tombstone_identity,
                ),
                "canonical exact deleted-NLB tombstone was not absence",
            )
            for label, expected_identity in (
                (
                    "wrong expected billing account",
                    {
                        **load_balancer_tombstone_identity,
                        "expected_billing_account_id": 9,
                    },
                ),
                (
                    "wrong expected deterministic name",
                    {
                        **load_balancer_tombstone_identity,
                        "expected_name": "k8s-other",
                    },
                ),
                (
                    "wrong expected network",
                    {
                        **load_balancer_tombstone_identity,
                        "expected_network_uuid": (
                            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
                        ),
                    },
                ),
            ):
                reject(
                    lambda: api.client().exact_absent(
                        f"network/load_balancers/{load_balancer_uuid}",
                        location="bkk01",
                        **expected_identity,
                    ),
                    f"deleted NLB tombstone with {label}",
                )
            Handler.routes[load_balancer_route] = (
                200,
                {},
                json.dumps(
                    {**deleted_load_balancer, "is_deleted": False}
                ).encode(),
            )
            require(
                not api.client().exact_absent(
                    f"network/load_balancers/{load_balancer_uuid}",
                    location="bkk01",
                ),
                "active exact NLB was mistaken for absence",
            )
            malformed_deleted_load_balancers = {
                "wrong UUID": {
                    **deleted_load_balancer,
                    "uuid": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                },
                "missing billing": {
                    key: value
                    for key, value in deleted_load_balancer.items()
                    if key != "billing_account_id"
                },
                "zero billing": {
                    **deleted_load_balancer,
                    "billing_account_id": 0,
                },
                "missing deletion time": {
                    key: value
                    for key, value in deleted_load_balancer.items()
                    if key != "deleted_at"
                },
                "malformed deletion state": {
                    **deleted_load_balancer,
                    "is_deleted": "true",
                },
                "missing ownership name": {
                    key: value
                    for key, value in deleted_load_balancer.items()
                    if key != "display_name"
                },
                "malformed network": {
                    **deleted_load_balancer,
                    "network_uuid": "not-a-uuid",
                },
                "malformed private address": {
                    **deleted_load_balancer,
                    "private_address": "not-an-ip",
                },
                "missing targets": {
                    key: value
                    for key, value in deleted_load_balancer.items()
                    if key != "targets"
                },
                "malformed forwarding rules": {
                    **deleted_load_balancer,
                    "forwarding_rules": [1],
                },
                "retained target": {
                    **deleted_load_balancer,
                    "targets": [{"uuid": disk_uuid}],
                },
                "case-confusable deletion state": {
                    **deleted_load_balancer,
                    "IS_DELETED": False,
                },
                "case-confusable billing": {
                    **deleted_load_balancer,
                    "Billing_Account_ID": 9,
                },
                "case-confusable network": {
                    **deleted_load_balancer,
                    "Network_UUID": (
                        "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
                    ),
                },
            }
            for label, value in malformed_deleted_load_balancers.items():
                Handler.routes[load_balancer_route] = (
                    200,
                    {},
                    json.dumps(value).encode(),
                )
                reject(
                    lambda: api.client().exact_absent(
                        f"network/load_balancers/{load_balancer_uuid}",
                        location="bkk01",
                        **load_balancer_tombstone_identity,
                    ),
                    f"deleted NLB tombstone with {label}",
                )
    finally:
        for name, value in old_proxy.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def test_list_identity_contracts() -> None:
    vm_uuid = "11111111-1111-4111-8111-111111111111"
    network_uuid = "22222222-2222-4222-8222-222222222222"
    firewall_uuid = "33333333-3333-4333-8333-333333333333"
    load_balancer_uuid = "44444444-4444-4444-8444-444444444444"
    disk_uuid = "55555555-5555-4555-8555-555555555555"
    boot_disk_uuid = "77777777-7777-4777-8777-777777777777"
    storage_pool_uuid = "88888888-8888-4888-8888-888888888888"
    package_uuid = "66666666-6666-4666-8666-666666666666"
    boot_disk = {
        "uuid": boot_disk_uuid,
        "user_id": 7,
        "billing_account_id": 8,
        "status": "Active",
        "size_gb": 60,
        "source_image_type": "OS_BASE",
        "source_image": "ubuntu-24.04",
        "created_at": "2026-07-17T10:00:00Z",
        "updated_at": "2026-07-17T10:01:00Z",
        "read_only_bootable": False,
        "snapshots": [],
        "storage_pool_uuid": storage_pool_uuid,
    }
    valid_lists = {
        "user-resource/vm/list": [
            {
                "uuid": vm_uuid,
                "name": "unit-vm",
                "status": "running",
                "description": "",
            }
        ],
        "network/networks": [{"uuid": network_uuid}],
        "network/firewalls": [
            {
                "uuid": firewall_uuid,
                "display_name": "unit-firewall",
                "resources_assigned": [],
                "rules": [],
            }
        ],
        "network/ip_addresses": [
            {
                "address": "203.0.113.10",
                "name": "",
                "assigned_to": None,
                "assigned_to_resource_type": None,
            }
        ],
        "network/load_balancers": [
            {
                "uuid": load_balancer_uuid,
                "display_name": "unit-load-balancer",
                "network_uuid": network_uuid,
                "private_address": "10.0.0.10",
                "targets": [],
                "forwarding_rules": [],
            }
        ],
        "storage/disks": [
            {
                "uuid": disk_uuid,
                "display_name": "pvc-unit-test",
                "billing_account_id": 8,
                "source_image_type": "EMPTY",
            },
            boot_disk,
        ],
        "storage/bucket/list": [{"name": "unit-bucket"}],
        "user-resource/service/packages": [{"uuid": package_uuid}],
    }
    for route, value in valid_lists.items():
        StrictInSpaceAPI._validate_endpoint_value(route, value)  # noqa: SLF001
    StrictInSpaceAPI._validate_endpoint_value(  # noqa: SLF001
        "network/ip_addresses",
        [
            {
                "address": "203.0.113.11",
                "name": "live-unassigned",
                "unassigned_at": "2026-07-17T09:54:01Z",
            }
        ],
    )
    StrictInSpaceAPI._validate_endpoint_value(  # noqa: SLF001
        "network/ip_addresses",
        [
            {
                "address": "203.0.113.12",
                "name": "live-newly-created",
                "uuid": "77777777-7777-4777-8777-777777777777",
                "id": 7,
                "user_id": 8,
                "billing_account_id": 9,
                "type": "public",
                "enabled": True,
                "is_deleted": False,
                "is_ipv6": False,
                "created_at": "2026-07-17T09:54:00Z",
                "updated_at": "2026-07-17T09:54:01Z",
            }
        ],
    )

    markerless_sparse_floating_ip = {
        "address": "203.0.113.12",
        "name": "live-newly-created",
        "uuid": "77777777-7777-4777-8777-777777777777",
        "id": 7,
        "user_id": 8,
        "billing_account_id": 9,
        "type": "public",
        "enabled": True,
        "is_deleted": False,
        "is_ipv6": False,
        "created_at": "2026-07-17T09:54:00Z",
        "updated_at": "2026-07-17T09:54:01Z",
    }
    invalid_rows = (
        (
            "storage/disks",
            [{"uuid": disk_uuid, "display_name": None}],
            "disk null display name",
        ),
        (
            "storage/disks",
            [
                {
                    "uuid": disk_uuid,
                    "display_name": "",
                    "billing_account_id": 8,
                    "source_image_type": "EMPTY",
                }
            ],
            "unnamed EMPTY disk",
        ),
        (
            "storage/disks",
            [{**boot_disk, "source_image_type": "EMPTY"}],
            "markerless EMPTY disk",
        ),
        (
            "storage/disks",
            [{**boot_disk, "status": "Provisioning"}],
            "non-Active markerless OS-base disk",
        ),
        (
            "storage/disks",
            [
                boot_disk,
                {"uuid": boot_disk_uuid, "display_name": "duplicate-disk"},
            ],
            "duplicate named and markerless disk identity",
        ),
        (
            "user-resource/vm/list",
            [{"uuid": vm_uuid, "name": "unit-vm"}],
            "VM status omission",
        ),
        (
            "network/firewalls",
            [{"uuid": firewall_uuid, "display_name": "unit-firewall", "rules": []}],
            "firewall assignment omission",
        ),
        (
            "network/ip_addresses",
            [{"address": "203.0.113.10", "name": ""}],
            "markerless sparse floating-IP stable identity omission",
        ),
        (
            "network/ip_addresses",
            [
                {
                    **markerless_sparse_floating_ip,
                    "assigned_to_resource_type": None,
                }
            ],
            "markerless sparse floating-IP null assignment type presence",
        ),
        (
            "network/ip_addresses",
            [
                {
                    **markerless_sparse_floating_ip,
                    "assigned_to_private_ip": "",
                }
            ],
            "markerless sparse floating-IP empty private-address presence",
        ),
        (
            "network/ip_addresses",
            [
                {
                    "address": "203.0.113.10",
                    "name": "",
                    "assigned_to": None,
                    "ASSIGNED_TO": vm_uuid,
                }
            ],
            "floating-IP non-canonical assignment field",
        ),
        (
            "network/ip_addresses",
            [
                {
                    "address": "203.0.113.10",
                    "name": "",
                    "unassigned_at": "2026-07-17T09:54:01Z",
                    "assigned_to_resource_type": "virtual_machine",
                }
            ],
            "floating-IP omitted assignment with contradictory resource type",
        ),
        (
            "network/ip_addresses",
            [
                {
                    "address": "203.0.113.10",
                    "name": "",
                    "unassigned_at": "2026-07-17T09:54:01Z",
                    "assigned_to_private_ip": "10.91.72.254",
                }
            ],
            "floating-IP omitted assignment with contradictory private address",
        ),
        (
            "network/load_balancers",
            [
                {
                    "uuid": load_balancer_uuid,
                    "display_name": "unit-load-balancer",
                    "network_uuid": network_uuid,
                    "private_address": "10.0.0.10",
                }
            ],
            "load-balancer relationship omission",
        ),
    )
    for route, value, label in invalid_rows:
        reject(
            lambda route=route, value=value: StrictInSpaceAPI._validate_endpoint_value(  # noqa: SLF001
                route, value
            ),
            label,
        )
    for missing_field in (
        "user_id",
        "billing_account_id",
        "status",
        "size_gb",
        "source_image_type",
        "source_image",
        "created_at",
        "updated_at",
        "read_only_bootable",
        "snapshots",
        "storage_pool_uuid",
    ):
        incomplete = dict(boot_disk)
        del incomplete[missing_field]
        reject(
            lambda incomplete=incomplete: StrictInSpaceAPI._validate_endpoint_value(  # noqa: SLF001
                "storage/disks", [incomplete]
            ),
            f"incomplete markerless OS-base disk missing {missing_field}",
        )


def test_unnamed_boot_disk_inventory_and_csi_ownership() -> None:
    account_inventory = load_script(
        "strict_unnamed_disk_inventory_test", "account-inventory.py"
    )
    boot_uuid = "11111111-aaaa-4111-8111-111111111111"
    csi_uuid = "22222222-bbbb-4222-8222-222222222222"
    deleted_uuid = "33333333-cccc-4333-8333-333333333333"
    original_api_get = account_inventory.api_get
    original_locations = account_inventory.locations
    account_inventory.locations = lambda: ["bkk01", "hkt01"]

    def inventory_api_get(path: str, location: str | None = None):
        if path == "storage/disks" and location == "bkk01":
            return [
                {
                    "uuid": boot_uuid,
                    "status": "Active",
                    "source_image_type": "OS_BASE",
                },
                {
                    "uuid": csi_uuid,
                    "status": "Active",
                    "display_name": "pvc-unit-test",
                    "source_image_type": "EMPTY",
                },
                {
                    "uuid": deleted_uuid,
                    "status": "deleted",
                    "source_image_type": "OS_BASE",
                },
            ]
        return []

    account_inventory.api_get = inventory_api_get
    try:
        complete = account_inventory.inventory()
    finally:
        account_inventory.api_get = original_api_get
        account_inventory.locations = original_locations
    require(
        complete["disks"]
        == [f"bkk01:{boot_uuid}", f"bkk01:{csi_uuid}"],
        "full account inventory did not retain an active unnamed boot-disk UUID",
    )

    cloud_audit = load_script(
        "strict_unnamed_disk_cloud_audit_test", "cloud-audit.py"
    )
    billing_account = 42
    disk_name = "pvc-unit-test"
    boot = {
        "uuid": boot_uuid,
        "billing_account_id": billing_account,
        "status": "Active",
        "source_image_type": "OS_BASE",
    }
    csi = {
        "uuid": csi_uuid,
        "display_name": disk_name,
        "billing_account_id": billing_account,
        "status": "Active",
        "source_image_type": "EMPTY",
    }
    selected = cloud_audit._select_owned_csi_disks(  # noqa: SLF001
        [boot, csi],
        known_disk_ids={csi_uuid},
        disk_uuid=csi_uuid,
        disk_name=disk_name,
        billing_account=billing_account,
    )
    require(
        selected == [{"uuid": csi_uuid, "name": disk_name}],
        "deterministic audit included a VM boot disk in CSI ownership",
    )
    require(
        cloud_audit._select_owned_csi_disks(  # noqa: SLF001
            [boot],
            known_disk_ids=set(),
            disk_uuid="",
            disk_name=disk_name,
            billing_account=billing_account,
        )
        == [],
        "an unclaimed VM boot disk entered the deterministic disk audit",
    )

    def reject_claim(disks, known, expected_uuid, expected_name, label):
        try:
            cloud_audit._select_owned_csi_disks(  # noqa: SLF001
                disks,
                known_disk_ids=known,
                disk_uuid=expected_uuid,
                disk_name=expected_name,
                billing_account=billing_account,
            )
        except SystemExit:
            return
        raise AssertionError(label)

    reject_claim(
        [boot],
        {boot_uuid},
        boot_uuid,
        disk_name,
        "journaled boot-disk UUID was accepted as CSI ownership",
    )
    reject_claim(
        [{**csi, "billing_account_id": billing_account + 1}],
        {csi_uuid},
        csi_uuid,
        disk_name,
        "wrong-account disk was accepted as CSI ownership",
    )
    reject_claim(
        [{**csi, "source_image_type": "OS_BASE"}],
        {csi_uuid},
        csi_uuid,
        disk_name,
        "named OS-base disk was accepted as CSI ownership",
    )
    other_uuid = "44444444-dddd-4444-8444-444444444444"
    reject_claim(
        [{**csi, "uuid": other_uuid}],
        {csi_uuid},
        csi_uuid,
        disk_name,
        "deterministic PVC name overrode the persisted disk UUID",
    )

    with tempfile.TemporaryDirectory() as temporary:
        state_path = pathlib.Path(temporary) / "state.json"
        state = {"knownDiskUUIDs": []}
        state_path.write_text(json.dumps(state), encoding="utf-8")
        state_path.chmod(0o600)
        result = {
            "vms": [],
            "firewalls": [],
            "floatingIPs": [],
            "loadBalancers": [],
            "disks": selected,
            "count": len(selected),
            "strictReadCount": 3,
        }
        cloud_audit.persist_audit_identities(
            state_path,
            state,
            result,
            allow_missing_state=False,
        )
        persisted = json.loads(state_path.read_text(encoding="utf-8"))
        require(
            persisted.get("knownDiskUUIDs") == [csi_uuid]
            and boot_uuid not in persisted.get("knownDiskUUIDs", []),
            "boot-disk UUID entered the durable CSI ownership journal",
        )


def test_stable_zero_proofs() -> None:
    account_inventory = load_script(
        "strict_account_inventory_test", "account-inventory.py"
    )
    empty = {
        name: [] for name in account_inventory.RESOURCE_PATHS
    }
    nonempty = {name: list(values) for name, values in empty.items()}
    nonempty["vms"] = ["bkk01:11111111-1111-4111-8111-111111111111"]
    snapshots = iter((empty, nonempty, nonempty))
    try:
        account_inventory.stable_inventory(
            inventory_reader=lambda: next(snapshots),
            read_count=3,
            delay_seconds=0,
            sleeper=lambda _seconds: None,
        )
    except SystemExit:
        pass
    else:
        raise AssertionError("transient empty account list produced a false baseline")

    cloud_audit = load_script("strict_cloud_audit_test", "cloud-audit.py")
    zero = {
        "vms": [],
        "firewalls": [],
        "floatingIPs": [],
        "loadBalancers": [],
        "disks": [],
        "count": 0,
    }
    present = {
        **zero,
        "vms": [{"uuid": "11111111-1111-4111-8111-111111111111", "name": "owned"}],
        "count": 1,
    }
    audit_snapshots = iter((zero, present, present))
    try:
        cloud_audit.stable_audit(
            {},
            "owner",
            "cluster",
            "pool",
            audit_reader=lambda *_args: next(audit_snapshots),
            read_count=3,
            delay_seconds=0,
            sleeper=lambda _seconds: None,
            exact_absence_reader=lambda _state: None,
        )
    except SystemExit:
        pass
    else:
        raise AssertionError("transient empty ownership list produced false final zero")

    calls = []
    stable = cloud_audit.stable_audit(
        {},
        "owner",
        "cluster",
        "pool",
        audit_reader=lambda *_args: zero,
        read_count=3,
        delay_seconds=0,
        sleeper=lambda _seconds: None,
        exact_absence_reader=lambda _state: calls.append("exact"),
    )
    require(
        stable["count"] == 0
        and stable["strictReadCount"] == 3
        and calls == ["exact", "exact", "exact"],
        "stable final zero did not require three exact corroboration passes",
    )

    disk_uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    load_balancer_uuid = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    exact_state = {
        "knownDiskUUIDs": [disk_uuid],
        "knownLoadBalancerUUIDs": [load_balancer_uuid],
        "pvcDiskName": "pvc-unit-test",
        "serviceLoadBalancerName": "k8s-unit-test",
    }

    class ExactAuditAPI:
        def __init__(self, lists):
            self.lists = lists
            self.exact_calls = []

        def get(self, path, *, location):
            require(location == "bkk01", "exact audit used another location")
            return self.lists.get(path, [])

        def exact_absent(self, path, *, location, **expected):
            require(location == "bkk01", "exact audit used another location")
            self.exact_calls.append((path, expected))
            return True

    exact_environment = {
        "INSPACE_LOCATION": "bkk01",
        "INSPACE_BILLING_ACCOUNT_ID": "8",
        "INSPACE_NETWORK_UUID": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    }
    old_exact_environment = {
        key: os.environ.get(key) for key in exact_environment
    }
    os.environ.update(exact_environment)
    try:
        exact_api = ExactAuditAPI({})
        cloud_audit.corroborate_exact_absence(
            exact_state,
            api=exact_api,
        )
        require(
            exact_api.exact_calls
            == [
                (
                    f"storage/disks/{disk_uuid}",
                    {
                        "expected_billing_account_id": 8,
                        "expected_name": "pvc-unit-test",
                    },
                ),
                (
                    f"network/load_balancers/{load_balancer_uuid}",
                    {
                        "expected_billing_account_id": 8,
                        "expected_name": "k8s-unit-test",
                        "expected_network_uuid": (
                            "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
                        ),
                    },
                ),
            ],
            "exact tombstone audit omitted its durable ownership identity",
        )

        listed_api = ExactAuditAPI(
            {"storage/disks": [{"uuid": disk_uuid}]}
        )
        try:
            cloud_audit.corroborate_exact_absence(
                {
                    "knownDiskUUIDs": [disk_uuid],
                    "pvcDiskName": "pvc-unit-test",
                },
                api=listed_api,
            )
        except SystemExit:
            pass
        else:
            raise AssertionError(
                "exact disk tombstone passed while its raw list row remained"
            )
        require(
            listed_api.exact_calls == [],
            "raw disk presence did not block exact tombstone processing",
        )

        class SequencedDiskAPI(ExactAuditAPI):
            def __init__(self):
                super().__init__({})
                self.disk_reads = 0

            def get(self, path, *, location):
                if path != "storage/disks":
                    return super().get(path, location=location)
                self.disk_reads += 1
                if self.disk_reads == 2:
                    return [{"uuid": disk_uuid}]
                return []

        sequenced_api = SequencedDiskAPI()
        try:
            cloud_audit.stable_audit(
                {
                    "knownDiskUUIDs": [disk_uuid],
                    "pvcDiskName": "pvc-unit-test",
                },
                "owner",
                "cluster",
                "pool",
                audit_reader=lambda *_args: zero,
                read_count=3,
                delay_seconds=0,
                sleeper=lambda _seconds: None,
                exact_absence_reader=lambda state: (
                    cloud_audit.corroborate_exact_absence(
                        state,
                        api=sequenced_api,
                    )
                ),
            )
        except SystemExit:
            pass
        else:
            raise AssertionError(
                "transient raw disk-list omission produced false final zero"
            )
    finally:
        for key, value in old_exact_environment.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    with tempfile.TemporaryDirectory() as temporary:
        missing_state = pathlib.Path(temporary) / "state.json"
        cloud_audit.persist_audit_identities(
            missing_state,
            {},
            stable,
            allow_missing_state=True,
        )
        require(
            not missing_state.exists(),
            "zero preflight must not synthesize an ownership journal",
        )
        try:
            cloud_audit.persist_audit_identities(
                missing_state,
                {},
                present,
                allow_missing_state=True,
            )
        except SystemExit:
            pass
        else:
            raise AssertionError(
                "preflight accepted owned resources without a journal"
            )
        try:
            cloud_audit.persist_audit_identities(
                missing_state,
                {},
                stable,
                allow_missing_state=False,
            )
        except SystemExit:
            pass
        else:
            raise AssertionError(
                "post-mutation audit accepted a missing ownership journal"
            )


def test_cloud_audit_expectations() -> None:
    cloud_audit = load_script(
        "strict_cloud_audit_expectation_test", "cloud-audit.py"
    )
    owner = "unit-owner"
    cluster = "unit-cluster"
    state = {"clusterResourceName": cluster}
    bootstrap = {
        "vms": [
            {
                "uuid": f"00000000-0000-4000-8000-00000000000{slot}",
                "name": f"{cluster}-cp{slot}",
            }
            for slot in range(3)
        ]
        + [
            {
                "uuid": "00000000-0000-4000-8000-000000000003",
                "name": f"{cluster}-bastion",
            }
        ],
        "firewalls": [
            {"uuid": "firewall-nodes", "name": f"{cluster}-nodes-{owner}"},
            {"uuid": "firewall-bastion", "name": f"{cluster}-bastion-{owner}"},
        ],
        "floatingIPs": [
            {
                "address": f"203.0.113.{10 + slot}",
                "name": f"{cluster}-cp{slot}-ip",
                "assigned_to": f"00000000-0000-4000-8000-00000000000{slot}",
            }
            for slot in range(3)
        ]
        + [
            {
                "address": "203.0.113.13",
                "name": f"{cluster}-bastion-ip",
                "assigned_to": "00000000-0000-4000-8000-000000000003",
            }
        ],
        "loadBalancers": [],
        "disks": [],
        "count": 10,
        "strictReadCount": 3,
    }
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = cloud_audit.emit_audit_result(
            bootstrap,
            "bootstrap-only",
            state=state,
            owner=owner,
            cluster=cluster,
        )
    require(status == 0, "bootstrap-only expectation rejected its target state")
    require(
        stdout.getvalue() == json.dumps(bootstrap, sort_keys=True) + "\n",
        "bootstrap-only success did not print canonical audit JSON",
    )
    require(stderr.getvalue() == "", "bootstrap-only success wrote an error")

    nonconverged = {**bootstrap, "disks": [{"uuid": "disk", "name": "pvc"}]}
    nonconverged["count"] = 11
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = cloud_audit.emit_audit_result(
            nonconverged,
            "bootstrap-only",
            state=state,
            owner=owner,
            cluster=cluster,
        )
    require(status == 1, "bootstrap-only expectation accepted an owned disk")
    require(
        stdout.getvalue() == json.dumps(nonconverged, sort_keys=True) + "\n",
        "nonconvergence did not preserve canonical audit JSON on stdout",
    )

    zero = {
        "vms": [],
        "firewalls": [],
        "floatingIPs": [],
        "loadBalancers": [],
        "disks": [],
        "count": 0,
        "strictReadCount": 3,
    }
    require(
        cloud_audit.expectation_converged(
            zero,
            "zero",
            state=state,
            owner=owner,
            cluster=cluster,
        ),
        "zero expectation rejected a stable empty audit",
    )
    require(
        not cloud_audit.expectation_converged(
            bootstrap,
            "zero",
            state=state,
            owner=owner,
            cluster=cluster,
        ),
        "zero expectation accepted remaining bootstrap resources",
    )
    malformed_bootstrap = {
        **bootstrap,
        "vms": [
            {key: value for key, value in item.items() if key != "uuid"}
            for item in bootstrap["vms"]
        ],
    }
    require(
        not cloud_audit.expectation_converged(
            malformed_bootstrap,
            "bootstrap-only",
            state=state,
            owner=owner,
            cluster=cluster,
        ),
        "bootstrap-only expectation accepted VM records without identities",
    )
    malformed = {**zero, "strictReadCount": "3"}
    stdout = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
        status = cloud_audit.emit_audit_result(
            malformed,
            "zero",
            state=state,
            owner=owner,
            cluster=cluster,
        )
    require(status == 1, "zero expectation accepted a malformed stable-read count")
    require(
        stdout.getvalue() == json.dumps(malformed, sort_keys=True) + "\n",
        "malformed nonconvergence did not preserve audit JSON on stdout",
    )


def main() -> None:
    test_transport_and_json_boundary()
    test_proxy_bypass_and_exact_absence()
    test_list_identity_contracts()
    test_unnamed_boot_disk_inventory_and_csi_ownership()
    test_stable_zero_proofs()
    test_cloud_audit_expectations()
    print("strict InSpace E2E API tests passed")


if __name__ == "__main__":
    main()
