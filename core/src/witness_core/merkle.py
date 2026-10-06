"""TIP-4 Merkle tree (RFC 6962 shape) over BLAKE2b-256."""

from __future__ import annotations

from dataclasses import dataclass
from hmac import compare_digest
from typing import Literal

from .ids import blake2b256


@dataclass(frozen=True)
class PathStep:
    """One audit-path step; `side` is where the *sibling* sits."""

    side: Literal["L", "R"]
    hash: bytes


def leaf_hash(value: bytes) -> bytes:
    return blake2b256(b"\x00" + value)


def node_hash(left: bytes, right: bytes) -> bytes:
    return blake2b256(b"\x01" + left + right)


def split_point(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def root(values: list[bytes]) -> bytes:
    n = len(values)
    if n == 0:
        return blake2b256(b"")
    if n == 1:
        return leaf_hash(values[0])
    k = split_point(n)
    return node_hash(root(values[:k]), root(values[k:]))


def audit_path(values: list[bytes], index: int) -> list[PathStep]:
    """Sibling steps from the leaf up to the root."""
    n = len(values)
    if not 0 <= index < n:
        raise IndexError(f"index {index} out of range for {n} leaves")
    if n == 1:
        return []
    k = split_point(n)
    if index < k:
        return [*audit_path(values[:k], index), PathStep("R", root(values[k:]))]
    return [*audit_path(values[k:], index - k), PathStep("L", root(values[:k]))]


def _is_h32(b: object) -> bool:
    return isinstance(b, bytes) and len(b) == 32


def verify(value: bytes, path: list[PathStep], expected_root: bytes) -> bool:
    if not _is_h32(value) or not _is_h32(expected_root):
        return False
    if any(not isinstance(s, PathStep) or not _is_h32(s.hash) for s in path):
        return False
    h = leaf_hash(value)
    for step in path:
        if step.side == "L":
            h = node_hash(step.hash, h)
        elif step.side == "R":
            h = node_hash(h, step.hash)
        else:
            return False
    return compare_digest(h, expected_root)
