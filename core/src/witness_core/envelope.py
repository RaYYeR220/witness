"""Signed `witness/v1` envelopes carried in IOTA tagged-data payloads.

The signature is Ed25519 over the JCS form of the envelope without `sig`.
`verify` is signature-level only; policy, replay and revocation checks
belong to callers.
"""

from __future__ import annotations

import base64
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import canon, verdicts


@dataclass(frozen=True)
class KeyInfo:
    kid: str
    ed25519_public: bytes | None
    x25519_public: bytes | None
    revoked_at_ms: int | None


@dataclass(frozen=True)
class EnvelopeCheck:
    verdict: str
    iss: str | None
    kid: str | None
    seq: int | None
    iat: int | None
    reason: str | None
    prev: str | None = None
    corr: str | None = None


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _signing_input(env: dict) -> bytes:
    return canon.jcs({k: v for k, v in env.items() if k != "sig"})


def seal(
    tag: str,
    body: dict | None,
    *,
    iss: str,
    kid: str,
    sign_key: Ed25519PrivateKey,
    seq: int,
    att_mode: Literal["producer", "relay"],
    att_sub: str | None = None,
    enc: dict | None = None,
    bix: list[str] | None = None,
    cmt: dict[str, str] | None = None,
    now_ms: int | None = None,
    nonce: bytes | None = None,
    prev: str | None = None,
    corr: str | None = None,
) -> dict:
    """Build and sign an envelope for `tag`."""
    att: dict[str, str] = {"mode": att_mode}
    if att_sub is not None:
        att["sub"] = att_sub
    env: dict[str, Any] = {
        "w": 1,
        "tag": tag,
        "iss": iss,
        "kid": kid,
        "seq": seq,
        "iat": int(time.time() * 1000) if now_ms is None else now_ms,
        "nonce": _b64(os.urandom(16) if nonce is None else nonce),
        "att": att,
        "body": body,
    }
    for key, value in (("enc", enc), ("bix", bix), ("cmt", cmt), ("prev", prev), ("corr", corr)):
        if value is not None:
            env[key] = value
    env["sig"] = _b64(sign_key.sign(_signing_input(env)))
    return env


def is_envelope(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and obj.get("w") == 1
        and not isinstance(obj.get("w"), bool)
        and isinstance(obj.get("sig"), str)
    )


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _malformed(reason: str) -> EnvelopeCheck:
    return EnvelopeCheck(verdicts.MALFORMED, None, None, None, None, reason)


def verify(
    env: dict, block_tag: str, resolve: Callable[[str], KeyInfo | None]
) -> EnvelopeCheck:
    """Check structure, tag binding, key resolution and signature."""
    if not is_envelope(env):
        return _malformed("not a witness/v1 envelope")
    for name in ("tag", "iss", "kid", "nonce"):
        if not isinstance(env.get(name), str):
            return _malformed(f"missing or invalid field: {name}")
    if not _is_int(env.get("seq")) or not _is_int(env.get("iat")):
        return _malformed("missing or invalid field: seq/iat")
    att = env.get("att")
    if not isinstance(att, dict) or att.get("mode") not in ("producer", "relay"):
        return _malformed("missing or invalid field: att")
    body = env.get("body")
    if body is not None and not isinstance(body, dict):
        return _malformed("invalid field: body")
    prev, corr = env.get("prev"), env.get("corr")
    for name, value in (("prev", prev), ("corr", corr)):
        if value is not None and not isinstance(value, str):
            return _malformed(f"invalid field: {name}")

    iss, kid, seq, iat = env["iss"], env["kid"], env["seq"], env["iat"]

    def result(verdict: str, reason: str | None = None) -> EnvelopeCheck:
        return EnvelopeCheck(verdict, iss, kid, seq, iat, reason, prev, corr)

    if env["tag"] != block_tag:
        return result(verdicts.FORGED, "envelope tag does not match block tag")
    if kid.split("#", 1)[0] != iss:
        return result(verdicts.FORGED, "kid does not belong to iss")
    info = resolve(kid)
    if info is None or info.ed25519_public is None:
        return result(verdicts.FORGED, "signing key not resolvable")
    try:
        sig = _unb64(env["sig"])
        Ed25519PublicKey.from_public_bytes(info.ed25519_public).verify(
            sig, _signing_input(env)
        )
    except (InvalidSignature, ValueError):
        return result(verdicts.FORGED, "signature invalid")
    if att["mode"] == "producer":
        return result(verdicts.PRODUCER_SIGNED)
    return result(verdicts.RELAY_ATTESTED)
