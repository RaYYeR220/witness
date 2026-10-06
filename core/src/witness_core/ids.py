"""Hashing and hex helpers for Stardust identifiers."""

from __future__ import annotations

import hashlib
import re


def blake2b256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def to_hex(b: bytes) -> str:
    return "0x" + b.hex()


def from_hex(s: str) -> bytes:
    body = s[2:] if s[:2] in ("0x", "0X") else s
    if not re.fullmatch(r"[0-9a-fA-F]*", body):
        raise ValueError(f"invalid hex string: {s!r}")
    if len(body) % 2:
        raise ValueError(f"odd-length hex string: {s!r}")
    try:
        return bytes.fromhex(body)
    except ValueError as exc:
        raise ValueError(f"invalid hex string: {s!r}") from exc
