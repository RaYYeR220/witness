"""Per-recipient encrypted payloads (JWE) and keyed blind-index tokens."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from jwcrypto import jwe as _jwe
from jwcrypto import jwk

from . import canon


class NotARecipient(Exception):
    """The JWE has no recipient entry for the given kid."""


class DecryptError(Exception):
    """The payload could not be decrypted or is not a JSON object."""


@dataclass(frozen=True)
class Recipient:
    kid: str
    x25519_public: bytes


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def encrypt_body(body: dict, recipients: list[Recipient]) -> dict:
    """Encrypt `body` for every recipient (General JSON Serialization)."""
    if not recipients:
        raise ValueError("at least one recipient is required")
    token = _jwe.JWE(canon.jcs(body), json.dumps({"enc": "A256GCM"}))
    for r in recipients:
        key = jwk.JWK(kty="OKP", crv="X25519", x=_b64(r.x25519_public))
        token.add_recipient(
            key, json.dumps({"alg": "ECDH-ES+A256KW", "kid": r.kid})
        )
    return json.loads(token.serialize())


def decrypt_body(jwe: dict, kid: str, x25519_private: X25519PrivateKey) -> dict:
    entries = jwe.get("recipients")
    if not isinstance(entries, list):
        raise DecryptError("not a general JWE")
    mine = [
        r for r in entries
        if isinstance(r, dict) and isinstance(r.get("header"), dict)
        and r["header"].get("kid") == kid
    ]
    if not mine:
        raise NotARecipient(kid)
    key = jwk.JWK(
        kty="OKP",
        crv="X25519",
        x=_b64(x25519_private.public_key().public_bytes_raw()),
        d=_b64(x25519_private.private_bytes_raw()),
    )
    try:
        # Only this recipient's entry, so other recipients' entries cannot interfere.
        single = {k: v for k, v in jwe.items() if k != "recipients"}
        single["recipients"] = mine[:1]
        token = _jwe.JWE()
        token.deserialize(json.dumps(single), key)
        body = json.loads(token.payload)
    except Exception as exc:
        raise DecryptError("decryption failed") from exc
    if not isinstance(body, dict):
        raise DecryptError("payload is not a JSON object")
    return body


def blind_token(search_key: bytes, kind: Literal["ie", "tag"], value: str) -> str:
    mac = hmac.new(search_key, f"{kind}:{value}".encode(), hashlib.sha256)
    return _b64(mac.digest())
