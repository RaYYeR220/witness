"""Salted commitments to sub-score values."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Any

from . import canon


def new_salt() -> bytes:
    return secrets.token_bytes(16)


def commit(value: Any, salt: bytes) -> str:
    digest = hashlib.blake2b(salt + canon.jcs(value), digest_size=32).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify(commitment: str, value: Any, salt: bytes) -> bool:
    return hmac.compare_digest(commitment.encode(), commit(value, salt).encode())
