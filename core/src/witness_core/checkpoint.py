"""Anchor checkpoints: a Merkle commitment to a contiguous milestone window.

The checkpoint JSON is what the anchor service writes to IOTA Rebased (or its
hash). `msRoot` is the TIP-4 root over the milestone ids from `from` to `to`
inclusive, so any milestone in the window can later be proven a member.
"""

from __future__ import annotations

import re
from typing import Any

from . import canon, merkle
from .ids import to_hex

KIND = "witness.checkpoint"
VERSION = 1

_H32 = re.compile(r"0x[0-9a-f]{64}")
_FIELDS = {
    "v", "kind", "network", "domain", "from", "to", "msRoot", "msgCount", "policyHash", "prev",
}
_MAX_INT = 2**53 - 1


def _uint(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= _MAX_INT


def _need32(b: bytes, field: str) -> None:
    if not isinstance(b, bytes) or len(b) != 32:
        raise ValueError(f"{field} must be 32 bytes")


def build(
    network: str,
    domain: str,
    frm: tuple[int, bytes],
    to: tuple[int, bytes],
    milestone_ids: list[bytes],
    msg_count: int,
    policy_hash: bytes,
    prev_hash: bytes | None,
) -> dict:
    """Checkpoint over `milestone_ids`, which must be exactly the window `frm..to`."""
    if not milestone_ids:
        raise ValueError("a checkpoint needs at least one milestone")
    for i, mid in enumerate(milestone_ids):
        _need32(mid, f"milestone_ids[{i}]")
    _need32(policy_hash, "policy_hash")
    if prev_hash is not None:
        _need32(prev_hash, "prev_hash")
    if not (_uint(frm[0]) and _uint(to[0]) and _uint(msg_count)):
        raise ValueError("indexes and msg_count must be unsigned integers")
    if to[0] - frm[0] + 1 != len(milestone_ids):
        raise ValueError(
            f"window {frm[0]}..{to[0]} does not match {len(milestone_ids)} milestone ids"
        )
    if milestone_ids[0] != frm[1] or milestone_ids[-1] != to[1]:
        raise ValueError("from/to ids must be the first and last milestone ids of the window")
    return {
        "v": VERSION,
        "kind": KIND,
        "network": network,
        "domain": domain,
        "from": {"index": frm[0], "id": to_hex(frm[1])},
        "to": {"index": to[0], "id": to_hex(to[1])},
        "msRoot": to_hex(merkle.root(milestone_ids)),
        "msgCount": msg_count,
        "policyHash": to_hex(policy_hash),
        "prev": None if prev_hash is None else to_hex(prev_hash),
    }


def hash(cp: dict) -> bytes:
    """BLAKE2b-256 over the JCS form of the checkpoint (shadows the builtin on purpose)."""
    return canon.canon_hash(cp)


def membership_path(milestone_ids: list[bytes], index_in_window: int) -> list[merkle.PathStep]:
    """Audit path proving milestone `index_in_window` is under `msRoot`."""
    return merkle.audit_path(milestone_ids, index_in_window)


def _bound_error(v: Any, name: str) -> str | None:
    if not isinstance(v, dict) or set(v) != {"index", "id"}:
        return f"{name} must be {{index, id}}"
    if not _uint(v["index"]):
        return f"{name}.index must be an unsigned integer"
    if not isinstance(v["id"], str) or not _H32.fullmatch(v["id"]):
        return f"{name}.id must be a 32-byte lowercase hex id"
    return None


def shape_error(cp: Any) -> str | None:
    """Describe the first structural problem of a checkpoint, or None if well formed."""
    if not isinstance(cp, dict):
        return "checkpoint is not an object"
    if set(cp) != _FIELDS:
        return "checkpoint fields do not match witness.checkpoint v1"
    if not _uint(cp["v"]) or cp["v"] != VERSION or cp["kind"] != KIND:
        return "not a witness.checkpoint v1"
    for name in ("network", "domain"):
        if not isinstance(cp[name], str):
            return f"{name} must be a string"
    for name in ("from", "to"):
        problem = _bound_error(cp[name], name)
        if problem:
            return problem
    if cp["from"]["index"] > cp["to"]["index"]:
        return "from.index is after to.index"
    for name in ("msRoot", "policyHash"):
        if not isinstance(cp[name], str) or not _H32.fullmatch(cp[name]):
            return f"{name} must be 32-byte lowercase hex"
    if not _uint(cp["msgCount"]):
        return "msgCount must be an unsigned integer"
    prev = cp["prev"]
    if prev is not None and not (isinstance(prev, str) and _H32.fullmatch(prev)):
        return "prev must be null or 32-byte lowercase hex"
    return None
