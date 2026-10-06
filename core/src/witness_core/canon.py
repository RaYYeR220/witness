"""RFC 8785 (JCS) canonicalization and hashing."""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785


def jcs(obj: Any) -> bytes:
    """Serialize `obj` to its canonical JSON form (RFC 8785)."""
    return rfc8785.dumps(obj)


def canon_hash(obj: Any) -> bytes:
    """BLAKE2b-256 of the canonical serialization of `obj`."""
    return hashlib.blake2b(jcs(obj), digest_size=32).digest()
