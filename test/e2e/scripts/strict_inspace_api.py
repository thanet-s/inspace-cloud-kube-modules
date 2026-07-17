#!/usr/bin/env python3
"""Strict, token-safe reader for the InSpace API used by destructive E2E.

The release E2E treats API reads as ownership and deletion evidence.  This
module therefore deliberately does not inherit urllib's permissive defaults:
it bypasses ambient proxies, never follows redirects, accepts only an exact
HTTP 200 for JSON reads, bounds and completely consumes the response body, and
validates the identities returned by every list/exact endpoint used by E2E.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable
from typing import Any


CANONICAL_API_ROOT = "https://api.inspace.cloud"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
LOCATION_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
FLOATING_IP_RESPONSE_FIELDS = (
    "uuid",
    "id",
    "address",
    "user_id",
    "billing_account_id",
    "type",
    "name",
    "enabled",
    "is_deleted",
    "is_ipv6",
    "is_virtual",
    "assigned_to",
    "assigned_to_resource_type",
    "assigned_to_private_ip",
    "created_at",
    "updated_at",
    "unassigned_at",
)


class StrictAPIError(RuntimeError):
    """An intentionally sanitized API failure that never contains credentials."""


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        del req, fp, msg, headers, newurl
        raise StrictAPIError(f"InSpace API rejected HTTP redirect status {code}")


def _canonical_uuid(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise StrictAPIError(f"{label} lacks a UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise StrictAPIError(f"{label} has a malformed UUID") from error
    canonical = str(parsed)
    if value != canonical:
        raise StrictAPIError(f"{label} UUID is not canonical lowercase text")
    return canonical


def _canonical_ip(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise StrictAPIError(f"{label} lacks an IP address")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as error:
        raise StrictAPIError(f"{label} has a malformed IP address") from error
    if str(parsed) != value:
        raise StrictAPIError(f"{label} IP address is not canonical text")
    return value


def _required_string(
    item: dict[str, Any],
    field: str,
    label: str,
    *,
    allow_empty: bool = False,
) -> str:
    if field not in item or not isinstance(item[field], str):
        raise StrictAPIError(f"{label} lacks string field {field}")
    value = item[field]
    if not allow_empty and not value.strip():
        raise StrictAPIError(f"{label} has empty field {field}")
    return value


def _required_list(item: dict[str, Any], field: str, label: str) -> list[Any]:
    if field not in item or not isinstance(item[field], list):
        raise StrictAPIError(f"{label} lacks complete array field {field}")
    return item[field]


def _required_positive_int(item: dict[str, Any], field: str, label: str) -> int:
    value = item.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StrictAPIError(f"{label} lacks positive integer field {field}")
    return value


def _reject_case_confusable_fields(
    item: dict[str, Any],
    canonical_fields: tuple[str, ...],
    label: str,
) -> None:
    for key in item:
        for canonical in canonical_fields:
            if key != canonical and key.casefold() == canonical.casefold():
                raise StrictAPIError(
                    f"{label} has non-canonical field {key}; want {canonical}"
                )


def _validate_deleted_disk_tombstone(
    value: dict[str, Any],
    *,
    expected_billing_account_id: int,
    expected_name: str,
) -> None:
    label = "exact deleted disk"
    _reject_case_confusable_fields(
        value,
        (
            "uuid",
            "user_id",
            "billing_account_id",
            "status",
            "size_gb",
            "source_image_type",
            "source_image",
            "created_at",
            "updated_at",
            "deleted_at",
            "display_name",
            "read_only_bootable",
            "snapshots",
            "storage_pool_uuid",
        ),
        label,
    )
    for field in ("user_id", "billing_account_id", "size_gb"):
        _required_positive_int(value, field, label)
    if value["billing_account_id"] != expected_billing_account_id:
        raise StrictAPIError(f"{label} belongs to another billing account")
    if value.get("status") != "Deleted":
        raise StrictAPIError(f"{label} is not explicitly Deleted")
    if value.get("source_image_type") != "EMPTY":
        raise StrictAPIError(f"{label} is not explicitly sourced from EMPTY")
    if value.get("source_image", "") != "":
        raise StrictAPIError(f"{label} unexpectedly retains a source image")
    if _required_string(value, "display_name", label) != expected_name:
        raise StrictAPIError(f"{label} has another deterministic name")
    _required_string(value, "created_at", label)
    _required_string(value, "updated_at", label)
    _required_string(value, "deleted_at", label)
    if value.get("read_only_bootable") is not False:
        raise StrictAPIError(f"{label} is not explicitly non-bootable")
    snapshots = _required_list(value, "snapshots", label)
    if snapshots:
        raise StrictAPIError(f"{label} retains snapshots")
    _canonical_uuid(value.get("storage_pool_uuid"), f"{label} storage pool")


def _validate_deleted_load_balancer_tombstone(
    value: dict[str, Any],
    *,
    expected_billing_account_id: int,
    expected_name: str,
    expected_network_uuid: str,
) -> None:
    label = "exact deleted load balancer"
    _reject_case_confusable_fields(
        value,
        (
            "uuid",
            "display_name",
            "user_id",
            "billing_account_id",
            "created_at",
            "updated_at",
            "is_deleted",
            "deleted_at",
            "private_address",
            "network_uuid",
            "forwarding_rules",
            "targets",
        ),
        label,
    )
    _validate_load_balancer_rows([value])
    for field in ("user_id", "billing_account_id"):
        _required_positive_int(value, field, label)
    if value["billing_account_id"] != expected_billing_account_id:
        raise StrictAPIError(f"{label} belongs to another billing account")
    if value["display_name"] != expected_name:
        raise StrictAPIError(f"{label} has another deterministic name")
    if value["network_uuid"] != expected_network_uuid:
        raise StrictAPIError(f"{label} belongs to another network")
    if value.get("is_deleted") is not True:
        raise StrictAPIError(f"{label} is not explicitly deleted")
    if value["targets"]:
        raise StrictAPIError(f"{label} retains targets")
    _required_string(value, "created_at", label)
    _required_string(value, "updated_at", label)
    _required_string(value, "deleted_at", label)


def _validate_rich_sparse_floating_ip_identity(
    row: dict[str, Any], label: str
) -> None:
    """Require stable ownership fields when no unassignment marker exists."""
    _canonical_uuid(row.get("uuid"), label)
    for field in ("id", "user_id", "billing_account_id"):
        value = row.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise StrictAPIError(f"{label} lacks positive integer field {field}")
    if row.get("type") != "public":
        raise StrictAPIError(f"{label} is not a public floating IP")
    for field in ("enabled", "is_deleted"):
        if not isinstance(row.get(field), bool):
            raise StrictAPIError(f"{label} lacks boolean field {field}")
    if row.get("is_ipv6") is not False:
        raise StrictAPIError(f"{label} is not explicitly IPv4")
    _required_string(row, "created_at", label)
    _required_string(row, "updated_at", label)


def _validate_locations(rows: list[Any]) -> None:
    identities = []
    for index, row in enumerate(rows):
        label = f"location list row {index}"
        if not isinstance(row, dict):
            raise StrictAPIError(f"{label} is not an object")
        slug = _required_string(row, "slug", label)
        if LOCATION_PATTERN.fullmatch(slug) is None:
            raise StrictAPIError(f"{label} has a non-canonical slug")
        identities.append(slug)
    _reject_duplicate_identities(identities, "location")


def _validate_vm_rows(rows: list[Any]) -> None:
    identities = []
    names = []
    for index, row in enumerate(rows):
        label = f"VM list row {index}"
        if not isinstance(row, dict):
            raise StrictAPIError(f"{label} is not an object")
        identities.append(_canonical_uuid(row.get("uuid"), label))
        names.append(_required_string(row, "name", label))
        _required_string(row, "status", label)
        _required_string(row, "description", label, allow_empty=True)
    _reject_duplicate_identities(identities, "VM UUID")
    _reject_duplicate_identities(names, "VM name")


def _validate_network_rows(rows: list[Any]) -> None:
    identities = []
    for index, row in enumerate(rows):
        label = f"network list row {index}"
        if not isinstance(row, dict):
            raise StrictAPIError(f"{label} is not an object")
        identities.append(_canonical_uuid(row.get("uuid"), label))
    _reject_duplicate_identities(identities, "network UUID")


def _validate_firewall_rows(rows: list[Any]) -> None:
    identities = []
    names = []
    for index, row in enumerate(rows):
        label = f"firewall list row {index}"
        if not isinstance(row, dict):
            raise StrictAPIError(f"{label} is not an object")
        identities.append(_canonical_uuid(row.get("uuid"), label))
        display_name = row.get("display_name")
        fallback_name = row.get("name")
        if not isinstance(display_name, str) and not isinstance(fallback_name, str):
            raise StrictAPIError(f"{label} lacks a string display name")
        effective_name = display_name or fallback_name or ""
        if not effective_name.strip():
            raise StrictAPIError(f"{label} has an empty display name")
        names.append(effective_name)
        assignments = _required_list(row, "resources_assigned", label)
        assignment_identities = []
        for assignment_index, assignment in enumerate(assignments):
            assignment_label = f"{label} assignment {assignment_index}"
            if not isinstance(assignment, dict):
                raise StrictAPIError(f"{assignment_label} is not an object")
            resource_type = _required_string(
                assignment, "resource_type", assignment_label
            )
            resource_uuid = _canonical_uuid(
                assignment.get("resource_uuid"), assignment_label
            )
            assignment_identities.append(f"{resource_type}\0{resource_uuid}")
        _reject_duplicate_identities(
            assignment_identities, f"{label} assignment"
        )
        rules = _required_list(row, "rules", label)
        if any(not isinstance(rule, dict) for rule in rules):
            raise StrictAPIError(f"{label} rules contain a non-object")
    _reject_duplicate_identities(identities, "firewall UUID")
    _reject_duplicate_identities(names, "firewall name")


def _validate_floating_ip_rows(rows: list[Any]) -> None:
    identities = []
    for index, row in enumerate(rows):
        label = f"floating-IP list row {index}"
        if not isinstance(row, dict):
            raise StrictAPIError(f"{label} is not an object")
        for key in row:
            for canonical in FLOATING_IP_RESPONSE_FIELDS:
                if key != canonical and key.casefold() == canonical.casefold():
                    raise StrictAPIError(
                        f"{label} has non-canonical field {key}; want {canonical}"
                    )
        identities.append(_canonical_ip(row.get("address"), label))
        _required_string(row, "name", label, allow_empty=True)
        if "assigned_to" not in row:
            # InSpace's live list and exact-address read models omit the
            # complete assignment tuple, including unassigned_at, for a newly
            # created but never-assigned address. Without the older
            # unassigned_at marker, require the complete stable ownership
            # identity before accepting the row for inventory/journaling.
            if "assigned_to_resource_type" in row:
                raise StrictAPIError(
                    f"{label} has assignment type without assigned_to"
                )
            if "assigned_to_private_ip" in row:
                raise StrictAPIError(
                    f"{label} has assigned private address without assigned_to"
                )
            if "unassigned_at" in row:
                _required_string(row, "unassigned_at", label)
            else:
                _validate_rich_sparse_floating_ip_identity(row, label)
            continue
        if row["assigned_to"] is not None and not isinstance(row["assigned_to"], str):
            raise StrictAPIError(f"{label} has malformed assignment state")
        if row["assigned_to"]:
            _canonical_uuid(row["assigned_to"], f"{label} assignment")
            _required_string(row, "assigned_to_resource_type", label)
        elif row.get("assigned_to_resource_type") not in (None, ""):
            raise StrictAPIError(f"{label} has contradictory assignment type")
        elif row.get("assigned_to_private_ip") not in (None, ""):
            raise StrictAPIError(
                f"{label} has contradictory assigned private address"
            )
    _reject_duplicate_identities(identities, "floating-IP address")


def _validate_load_balancer_rows(rows: list[Any]) -> None:
    identities = []
    names = []
    for index, row in enumerate(rows):
        label = f"load-balancer list row {index}"
        if not isinstance(row, dict):
            raise StrictAPIError(f"{label} is not an object")
        identities.append(_canonical_uuid(row.get("uuid"), label))
        names.append(_required_string(row, "display_name", label))
        _canonical_uuid(row.get("network_uuid"), f"{label} network")
        _canonical_ip(row.get("private_address"), f"{label} private address")
        for field in ("targets", "forwarding_rules"):
            values = _required_list(row, field, label)
            if any(not isinstance(value, dict) for value in values):
                raise StrictAPIError(f"{label} {field} contain a non-object")
    _reject_duplicate_identities(identities, "load-balancer UUID")
    _reject_duplicate_identities(names, "load-balancer name")


def _validate_disk_rows(rows: list[Any]) -> None:
    identities = []
    for index, row in enumerate(rows):
        label = f"disk list row {index}"
        if not isinstance(row, dict):
            raise StrictAPIError(f"{label} is not an object")
        identities.append(_canonical_uuid(row.get("uuid"), label))
        if "display_name" in row:
            # CSI and user-created EMPTY disks are name-addressable.  An empty
            # or non-string value is not equivalent to the live boot-disk
            # representation, which omits this field altogether.
            _required_string(row, "display_name", label)
            continue

        # InSpace omits display_name from the location disk inventory for a
        # VM's OS_BASE primary disk.  Accept only the complete live boot-disk
        # shape; otherwise an incomplete or unnamed EMPTY CSI row could become
        # invisible to deterministic ownership discovery.
        for field in ("user_id", "billing_account_id", "size_gb"):
            value = row.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise StrictAPIError(
                    f"{label} unnamed OS-base disk lacks positive integer field {field}"
                )
        if row.get("status") != "Active":
            raise StrictAPIError(
                f"{label} unnamed OS-base disk is not explicitly Active"
            )
        if row.get("source_image_type") != "OS_BASE":
            raise StrictAPIError(
                f"{label} unnamed disk is not explicitly sourced from OS_BASE"
            )
        _required_string(row, "source_image", label)
        _canonical_uuid(
            row.get("storage_pool_uuid"),
            f"{label} storage pool",
        )
        if row.get("read_only_bootable") is not False:
            raise StrictAPIError(
                f"{label} unnamed OS-base disk lacks explicit non-bootable readback"
            )
        snapshots = _required_list(row, "snapshots", label)
        if any(not isinstance(snapshot, dict) for snapshot in snapshots):
            raise StrictAPIError(f"{label} snapshots contain a non-object")
        _required_string(row, "created_at", label)
        _required_string(row, "updated_at", label)
    _reject_duplicate_identities(identities, "disk UUID")


def _validate_bucket_rows(rows: list[Any]) -> None:
    identities = []
    for index, row in enumerate(rows):
        label = f"bucket list row {index}"
        if not isinstance(row, dict):
            raise StrictAPIError(f"{label} is not an object")
        identities.append(_required_string(row, "name", label))
    _reject_duplicate_identities(identities, "bucket name")


def _validate_package_rows(rows: list[Any]) -> None:
    identities = []
    for index, row in enumerate(rows):
        label = f"service-package list row {index}"
        if not isinstance(row, dict):
            raise StrictAPIError(f"{label} is not an object")
        identities.append(_canonical_uuid(row.get("uuid"), label))
    _reject_duplicate_identities(identities, "service-package UUID")


def _reject_duplicate_identities(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise StrictAPIError(f"InSpace API returned duplicate {label} identities")


LIST_VALIDATORS: dict[str, Callable[[list[Any]], None]] = {
    "config/locations": _validate_locations,
    "user-resource/vm/list": _validate_vm_rows,
    "network/networks": _validate_network_rows,
    "network/firewalls": _validate_firewall_rows,
    "network/ip_addresses": _validate_floating_ip_rows,
    "network/load_balancers": _validate_load_balancer_rows,
    "storage/disks": _validate_disk_rows,
    "storage/bucket/list": _validate_bucket_rows,
    "user-resource/service/packages": _validate_package_rows,
}


def _pairs_without_duplicates(
    pairs_value: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs_value:
        if key in result:
            raise StrictAPIError(
                "InSpace API returned JSON with a duplicate object key"
            )
        result[key] = value
    return result


def _json_without_duplicates(raw: bytes) -> Any:
    if not raw or not raw.strip():
        raise StrictAPIError("InSpace API returned an empty response body")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise StrictAPIError("InSpace API returned non-UTF-8 JSON") from error

    def reject_constant(_value: str) -> None:
        raise StrictAPIError("InSpace API returned a non-finite JSON number")

    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=reject_constant,
        )
    except StrictAPIError:
        raise
    except (json.JSONDecodeError, ValueError) as error:
        raise StrictAPIError("InSpace API returned malformed or trailing JSON") from error
    if value is None:
        raise StrictAPIError("InSpace API returned JSON null")
    if value == {}:
        raise StrictAPIError("InSpace API returned an empty JSON object")
    return value


def _validate_api_root(base_url: str, *, allow_loopback_for_tests: bool) -> str:
    if base_url == CANONICAL_API_ROOT:
        return base_url
    parsed = urllib.parse.urlsplit(base_url)
    if (
        allow_loopback_for_tests
        and parsed.scheme in ("http", "https")
        and parsed.hostname in ("127.0.0.1", "::1")
        and parsed.username is None
        and parsed.password is None
        and parsed.path in ("", "/")
        and not parsed.query
        and not parsed.fragment
    ):
        return base_url.rstrip("/")
    raise StrictAPIError(
        "destructive E2E requires the canonical https://api.inspace.cloud API root"
    )


class StrictInSpaceAPI:
    """A no-proxy, no-redirect, bounded InSpace JSON reader."""

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        user_agent: str,
        allow_loopback_for_tests: bool = False,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if not isinstance(base_url, str):
            raise StrictAPIError("InSpace API root must be text")
        self.base_url = _validate_api_root(
            base_url,
            allow_loopback_for_tests=allow_loopback_for_tests,
        )
        if not isinstance(token, str) or not token:
            raise StrictAPIError("InSpace API token is required")
        if "\r" in token or "\n" in token:
            raise StrictAPIError("InSpace API token is malformed")
        self._token = token
        self._user_agent = user_agent
        self._proxy_handler = urllib.request.ProxyHandler({})
        handlers: list[urllib.request.BaseHandler] = [
            self._proxy_handler,
            _RejectRedirects(),
        ]
        if self.base_url.startswith("https://"):
            handlers.append(
                urllib.request.HTTPSHandler(
                    context=ssl_context or ssl.create_default_context()
                )
            )
        self._opener = urllib.request.build_opener(*handlers)

    @classmethod
    def from_environment(cls, *, user_agent: str) -> "StrictInSpaceAPI":
        return cls(
            base_url=os.environ["INSPACE_API_URL"],
            token=os.environ["INSPACE_API_TOKEN"],
            user_agent=user_agent,
        )

    def _url(self, path: str, location: str | None) -> tuple[str, str]:
        if not isinstance(path, str) or not path or path.startswith("/"):
            raise StrictAPIError("InSpace API path must be a non-empty relative path")
        parsed_path = urllib.parse.urlsplit(path)
        if (
            parsed_path.scheme
            or parsed_path.netloc
            or parsed_path.fragment
            or not parsed_path.path
            or any(part in ("", ".", "..") for part in parsed_path.path.split("/"))
        ):
            raise StrictAPIError("InSpace API path is not canonical")
        if location is None:
            endpoint = f"v1/{path}"
        else:
            if not isinstance(location, str) or LOCATION_PATTERN.fullmatch(location) is None:
                raise StrictAPIError("InSpace location is not canonical")
            endpoint = f"v1/{location}/{path}"
        url = f"{self.base_url}/{endpoint}"
        return url, parsed_path.path

    @staticmethod
    def _read_complete(response, endpoint_label: str) -> bytes:  # noqa: ANN001
        raw_length = response.headers.get("Content-Length")
        expected_length: int | None = None
        if raw_length is not None:
            if not raw_length.isascii() or not raw_length.isdigit():
                raise StrictAPIError(
                    f"{endpoint_label} returned malformed Content-Length"
                )
            expected_length = int(raw_length)
            if expected_length > MAX_RESPONSE_BYTES:
                raise StrictAPIError(
                    f"{endpoint_label} response exceeds the 4-MiB limit"
                )
        output = bytearray()
        try:
            while len(output) <= MAX_RESPONSE_BYTES:
                remaining = MAX_RESPONSE_BYTES + 1 - len(output)
                chunk = response.read(min(64 * 1024, remaining))
                if not chunk:
                    break
                output.extend(chunk)
        except Exception as error:
            raise StrictAPIError(
                f"{endpoint_label} response body was not completely readable"
            ) from error
        if len(output) > MAX_RESPONSE_BYTES:
            raise StrictAPIError(
                f"{endpoint_label} response exceeds the 4-MiB limit"
            )
        if expected_length is not None and len(output) != expected_length:
            raise StrictAPIError(
                f"{endpoint_label} response body was truncated"
            )
        return bytes(output)

    def _open(
        self,
        url: str,
        endpoint_label: str,
        *,
        allowed_statuses: set[int],
    ) -> tuple[int, bytes]:
        request = urllib.request.Request(
            url,
            headers={
                "apikey": self._token,
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "User-Agent": self._user_agent,
            },
            method="GET",
        )
        try:
            response = self._opener.open(request, timeout=60)
        except urllib.error.HTTPError as error:
            response = error
        except StrictAPIError:
            raise
        except Exception as error:
            raise StrictAPIError(
                f"{endpoint_label} transport failed without an authoritative response"
            ) from error
        try:
            final_url = response.geturl()
            if final_url != url:
                raise StrictAPIError(
                    f"{endpoint_label} response URL differs from the requested URL"
                )
            status = response.getcode()
            body = self._read_complete(response, endpoint_label)
            if status not in allowed_statuses:
                raise StrictAPIError(
                    f"{endpoint_label} returned unexpected HTTP status {status}"
                )
            return status, body
        finally:
            response.close()

    def get(self, path: str, *, location: str | None) -> Any:
        url, route = self._url(path, location)
        endpoint_label = f"InSpace GET {route}"
        status, raw = self._open(url, endpoint_label, allowed_statuses={200})
        if status != 200:
            raise AssertionError("unreachable: strict JSON GET accepted non-200")
        value = _json_without_duplicates(raw)
        self._validate_endpoint_value(path, value)
        return value

    def exact_absent(
        self,
        path: str,
        *,
        location: str,
        expected_billing_account_id: int | None = None,
        expected_name: str | None = None,
        expected_network_uuid: str | None = None,
    ) -> bool:
        """Corroborate absence on one exact identity endpoint.

        Exact object APIs use HTTP 404 for missing disk/NLB/FIP objects.
        InSpace's VM endpoint additionally documents a legacy HTTP 400 body
        containing the exact requested VM UUID.  Every other response remains
        a hard failure; callers must also corroborate absence through stable
        list snapshots.
        """

        url, route = self._url(path, location)
        endpoint_label = f"InSpace exact GET {route}"
        status, raw = self._open(
            url,
            endpoint_label,
            allowed_statuses={200, 400, 404},
        )
        if status == 200:
            value = _json_without_duplicates(raw)
            self._validate_endpoint_value(path, value)
            parsed = urllib.parse.urlsplit(path)
            route = parsed.path
            if route.startswith("storage/disks/"):
                disk_status = value.get("status")
                if not isinstance(disk_status, str):
                    raise StrictAPIError(
                        f"{endpoint_label} lacks string disk status"
                    )
                if disk_status == "Deleted":
                    if (
                        isinstance(expected_billing_account_id, bool)
                        or not isinstance(expected_billing_account_id, int)
                        or expected_billing_account_id < 1
                        or not isinstance(expected_name, str)
                        or not expected_name
                    ):
                        raise StrictAPIError(
                            f"{endpoint_label} lacks expected tombstone identity"
                        )
                    _validate_deleted_disk_tombstone(
                        value,
                        expected_billing_account_id=expected_billing_account_id,
                        expected_name=expected_name,
                    )
                    return True
            if route.startswith("network/load_balancers/"):
                is_deleted = value.get("is_deleted")
                if not isinstance(is_deleted, bool):
                    raise StrictAPIError(
                        f"{endpoint_label} lacks boolean deletion state"
                    )
                if is_deleted:
                    if (
                        isinstance(expected_billing_account_id, bool)
                        or not isinstance(expected_billing_account_id, int)
                        or expected_billing_account_id < 1
                        or not isinstance(expected_name, str)
                        or not expected_name
                        or not isinstance(expected_network_uuid, str)
                        or not expected_network_uuid
                    ):
                        raise StrictAPIError(
                            f"{endpoint_label} lacks expected tombstone identity"
                        )
                    expected_network_uuid = _canonical_uuid(
                        expected_network_uuid,
                        "expected tombstone network",
                    )
                    _validate_deleted_load_balancer_tombstone(
                        value,
                        expected_billing_account_id=expected_billing_account_id,
                        expected_name=expected_name,
                        expected_network_uuid=expected_network_uuid,
                    )
                    return True
            return False
        if status == 404:
            return True
        parsed = urllib.parse.urlsplit(path)
        query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
        requested = query.get("uuid", [])
        if (
            parsed.path != "user-resource/vm"
            or len(requested) != 1
            or _canonical_uuid(requested[0], "requested VM") != requested[0]
        ):
            raise StrictAPIError(
                f"{endpoint_label} returned non-authoritative HTTP 400"
            )
        payload = _json_without_duplicates(raw)
        expected = "No such virtual machine exists: " + requested[0]
        if (
            not isinstance(payload, dict)
            or set(payload) != {"errors"}
            or not isinstance(payload["errors"], dict)
            or set(payload["errors"]) != {"Error"}
            or not isinstance(payload["errors"]["Error"], str)
            or payload["errors"]["Error"] != expected
        ):
            raise StrictAPIError(
                f"{endpoint_label} returned non-authoritative HTTP 400"
            )
        return True

    @staticmethod
    def _validate_endpoint_value(path: str, value: Any) -> None:
        parsed = urllib.parse.urlsplit(path)
        route = parsed.path
        validator = LIST_VALIDATORS.get(route)
        if validator is not None:
            if not isinstance(value, list):
                raise StrictAPIError(f"{route} did not return an array")
            validator(value)
            return
        if not isinstance(value, dict):
            raise StrictAPIError(f"{route} did not return an object")

        if route == "user-resource/vm":
            query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
            requested = query.get("uuid", [])
            if len(requested) != 1:
                raise StrictAPIError("exact VM lookup lacks one UUID query")
            expected = _canonical_uuid(requested[0], "requested VM")
            if _canonical_uuid(value.get("uuid"), "exact VM") != expected:
                raise StrictAPIError("exact VM response identity mismatches request")
            _required_string(value, "name", "exact VM")
            _required_list(value, "storage", "exact VM")
            return

        exact_routes = (
            ("network/network/", "uuid", "network"),
            ("storage/disks/", "uuid", "disk"),
            ("network/load_balancers/", "uuid", "load balancer"),
            ("network/ip_addresses/", "address", "floating IP"),
        )
        for prefix, field, label in exact_routes:
            if not route.startswith(prefix):
                continue
            requested = urllib.parse.unquote(route.removeprefix(prefix))
            if "/" in requested or not requested:
                raise StrictAPIError(f"exact {label} path is malformed")
            if field == "uuid":
                expected = _canonical_uuid(requested, f"requested {label}")
                actual = _canonical_uuid(value.get(field), f"exact {label}")
            else:
                expected = _canonical_ip(requested, f"requested {label}")
                actual = _canonical_ip(value.get(field), f"exact {label}")
            if actual != expected:
                raise StrictAPIError(
                    f"exact {label} response identity mismatches request"
                )
            if label == "network":
                members = _required_list(value, "vm_uuids", "exact network")
                canonical_members = [
                    _canonical_uuid(member, "exact network VM member")
                    for member in members
                ]
                _reject_duplicate_identities(
                    canonical_members, "exact network VM-member"
                )
            elif label == "load balancer":
                _required_list(value, "targets", "exact load balancer")
                _required_list(value, "forwarding_rules", "exact load balancer")
            return
        raise StrictAPIError(f"unrecognized InSpace GET route {route}")


def location_api_get(path: str, *, user_agent: str) -> Any:
    return StrictInSpaceAPI.from_environment(user_agent=user_agent).get(
        path,
        location=os.environ["INSPACE_LOCATION"],
    )


def scoped_api_get(
    path: str,
    *,
    location: str | None,
    user_agent: str,
) -> Any:
    return StrictInSpaceAPI.from_environment(user_agent=user_agent).get(
        path,
        location=location,
    )
