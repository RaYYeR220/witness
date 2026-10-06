"""Hashing and hex helpers for Stardust identifiers, and the canonical did:iota form."""

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


# A did:iota DID names its Identity object: `did:iota:[<network>:]0x<64 lowercase hex>`, as
# the anchor service writes it (mainnet DIDs omit the network).
_CANONICAL_IOTA_DID = re.compile(r"did:iota:(?:[a-z0-9]{1,8}:)?0x[0-9a-f]{64}")
NON_CANONICAL_DID = "non-canonical DID"


def is_canonical_did(did: str) -> bool:
    """False for a did:iota DID not in canonical form (upper-case hex, wrong length, ...);
    True for any other string. A non-canonical did:iota DID is never looked up: the anchor
    would normalise it and answer for another spelling, which no caller can match."""
    return not did.startswith("did:iota:") or _CANONICAL_IOTA_DID.fullmatch(did) is not None
