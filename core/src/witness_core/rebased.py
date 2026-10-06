"""Reads the anchor's Audit Trail record straight from the pinned IOTA Rebased JSON-RPC.

Step 5 of the verifier ladder needs the on-chain record of the checkpoint. This module
fetches it from a fullnode the verifier pins, never through the anchor service: the trail
object must be of the pinned Audit Trail package, the record is read from its records
table, and the checkpoint is taken from the record's own data (the metadata hash must agree
with it), so core recomputes the hash from on-chain bytes.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import checkpoint
from .ids import to_hex

RECORD_KIND = checkpoint.KIND
_NOT_FOUND = "dynamicFieldNotFound"
_MAX_INDEX = 2**53 - 1


class RebasedError(Exception):
    """The chain could not be read, or what it returned is not the pinned trail's record."""


def _rpc(post: Callable[..., httpx.Response], url: str, method: str, params: list,
         timeout: float) -> Any:
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    try:
        resp = post(url, json=body, timeout=timeout, follow_redirects=False)
    except httpx.HTTPError as exc:
        raise RebasedError(f"{method}: {type(exc).__name__}") from None
    if resp.status_code != 200:
        raise RebasedError(f"{method}: HTTP {resp.status_code}")
    try:
        doc = resp.json()
    except ValueError:
        raise RebasedError(f"{method}: response is not JSON") from None
    if not isinstance(doc, dict):
        raise RebasedError(f"{method}: unexpected response")
    if "error" in doc:
        err = doc["error"]
        code = err.get("code") if isinstance(err, dict) else None
        raise RebasedError(f"{method}: RPC error {code}")
    return doc.get("result")


def _get(obj: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _records_table(post: Callable[..., httpx.Response], url: str, trail_id: str,
                   package_id: str, timeout: float) -> str:
    result = _rpc(post, url, "iota_getObject",
                  [trail_id, {"showContent": True, "showType": True}], timeout)
    kind = _get(result, "data", "type")
    if not isinstance(kind, str) or not kind.startswith(f"{package_id}::main::AuditTrail<"):
        raise RebasedError("the pinned trail object is not an Audit Trail of the pinned package")
    table = _get(result, "data", "content", "fields", "records", "fields", "id", "id")
    if not isinstance(table, str):
        raise RebasedError("trail has no records table")
    return table


def _record_text(fields: dict) -> str:
    data = fields.get("data")
    variant = data.get("variant") if isinstance(data, dict) else None
    pos0 = _get(data, "fields", "pos0")
    if variant == "Text" and isinstance(pos0, str):
        return pos0
    if variant == "Bytes" and isinstance(pos0, list):
        try:
            return bytes(pos0).decode("utf-8")
        except (ValueError, TypeError):
            raise RebasedError("record bytes are not UTF-8 text") from None
    raise RebasedError(f"unknown record data variant {variant!r}")


def _scheme_ok(url: str, allow_http: bool) -> bool:
    scheme = urlsplit(url).scheme
    return scheme == "https" or (allow_http and scheme == "http")


def fetch_record(
    rpc_url: str,
    trail_id: str,
    index: int,
    *,
    package_id: str,
    post: Callable[..., httpx.Response] = httpx.post,
    timeout: float = 15,
    allow_http: bool = False,
) -> dict | None:
    """The checkpoint record `index` of the trail, or None when the trail has no such record.

    Returns `{"checkpoint", "checkpointHash"}` where the checkpoint is parsed from the
    on-chain record data and the hash is the record metadata's, accepted only if it equals
    the hash recomputed from that data. Anything else that is wrong raises `RebasedError`.
    """
    if not _scheme_ok(rpc_url, allow_http):
        raise RebasedError("the Rebased RPC must be an https URL")
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index <= _MAX_INDEX:
        raise RebasedError("record index must be a non-negative integer")
    table = _records_table(post, rpc_url, trail_id, package_id, timeout)
    result = _rpc(post, rpc_url, "iotax_getDynamicFieldObject",
                  [table, {"type": "u64", "value": str(index)}], timeout)
    if _get(result, "error", "code") == _NOT_FOUND:
        return None
    if _get(result, "error") is not None:
        raise RebasedError(f"reading record {index}: {_get(result, 'error', 'code')}")
    fields = _get(result, "data", "content", "fields", "value", "fields", "value", "fields")
    if not isinstance(fields, dict):
        raise RebasedError(f"record {index} has an unexpected shape")
    try:
        sequence = int(fields.get("sequence_number"))
    except (TypeError, ValueError):
        raise RebasedError(f"record {index} has no sequence number") from None
    if sequence != index:
        raise RebasedError(f"record {index} reports sequence {sequence}")
    try:
        cp = json.loads(_record_text(fields))
        problem = checkpoint.shape_error(cp)
        if problem is not None:
            raise RebasedError(f"record data is not a checkpoint: {problem}")
        digest = to_hex(checkpoint.hash(cp))
        meta = json.loads(fields.get("metadata") or "null")
    except RebasedError:
        raise
    except (ValueError, TypeError, RecursionError):
        raise RebasedError("record data or metadata is not valid JSON") from None
    if not isinstance(meta, dict) or meta.get("kind") != RECORD_KIND:
        raise RebasedError("record metadata does not describe a witness checkpoint")
    if meta.get("checkpointHash") != digest:
        raise RebasedError("record metadata hash differs from the hash of its data")
    return {"checkpoint": cp, "checkpointHash": digest}


def make_fetcher(
    cfg: Any,
    *,
    rpc_url: str | None = None,
    post: Callable[..., httpx.Response] = httpx.post,
    timeout: float = 15,
    allow_http: bool = False,
) -> Callable[[dict], dict | None]:
    """The `fetch_anchor_record` callback of `bundle.verify`, bound to the pinned config.

    The trail and package come from `cfg` only; the bundle supplies the record index.
    `rpc_url` overrides the pinned `cfg.rebased_rpc`.
    """

    def fetch(anchor: dict) -> dict | None:
        url = rpc_url or cfg.rebased_rpc
        if not url or not cfg.trail_id or not cfg.audit_trail_package:
            raise RebasedError("verifier config pins no Rebased RPC, trail or Audit Trail package")
        return fetch_record(url, cfg.trail_id, anchor["rebased"]["record"],
                            package_id=cfg.audit_trail_package, post=post, timeout=timeout,
                            allow_http=allow_http)

    return fetch
