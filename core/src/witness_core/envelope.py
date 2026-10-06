"""Signed `witness/v1` envelopes carried in IOTA tagged-data payloads.

The signature is Ed25519 over the JCS form of the envelope without `sig`.
`verify` is signature-level only; policy, replay and revocation checks
belong to callers.
"""

from __future__ import annotations

import base64
import os
import re
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


_MAX_INT = 2**53 - 1
_SIG_RE = re.compile(r"[A-Za-z0-9_-]{86}")
_NONCE_RE = re.compile(r"[A-Za-z0-9_-]{22}")
_PREV_RE = re.compile(r"0x[0-9a-f]{64}")
_KEYS = {
    "w", "tag", "iss", "kid", "seq", "iat", "nonce", "att",
    "body", "enc", "bix", "cmt", "prev", "corr", "sig",
}


def _is_uint(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= _MAX_INT


def _canonical_b64(s: Any, pattern: re.Pattern[str]) -> bytes | None:
    """Decode strict unpadded base64url; None unless `s` is the canonical encoding."""
    if not isinstance(s, str) or not pattern.fullmatch(s):
        return None
    try:
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except ValueError:
        return None
    return raw if _b64(raw) == s else None


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
    if enc is not None and body is not None:
        raise ValueError("envelope carries either body or enc, not both")
    if not _is_uint(seq):
        raise ValueError("seq must be an integer in [0, 2^53-1]")
    iat = int(time.time() * 1000) if now_ms is None else now_ms
    if not _is_uint(iat):
        raise ValueError("iat must be an integer in [0, 2^53-1]")
    if nonce is not None and len(nonce) != 16:
        raise ValueError("nonce must be 16 bytes")
    env: dict[str, Any] = {
        "w": 1,
        "tag": tag,
        "iss": iss,
        "kid": kid,
        "seq": seq,
        "iat": iat,
        "nonce": _b64(os.urandom(16) if nonce is None else nonce),
        "att": att,
    }
    if enc is None:
        env["body"] = body
    for key, value in (("enc", enc), ("bix", bix), ("cmt", cmt), ("prev", prev), ("corr", corr)):
        if value is not None:
            env[key] = value
    env["sig"] = _b64(sign_key.sign(_signing_input(env)))
    return env


def is_envelope(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and isinstance(obj.get("w"), int)
        and not isinstance(obj.get("w"), bool)
        and obj["w"] == 1
        and isinstance(obj.get("sig"), str)
    )


def _malformed(reason: str) -> EnvelopeCheck:
    return EnvelopeCheck(verdicts.MALFORMED, None, None, None, None, reason)


def _shape_error(env: dict) -> str | None:
    """Return a description of the first structural problem, or None."""
    if not is_envelope(env):
        return "not a witness/v1 envelope"
    if set(env) - _KEYS:
        return "unknown top-level field"
    for name in ("tag", "iss", "kid"):
        if not isinstance(env.get(name), str):
            return f"missing or invalid field: {name}"
    if not _is_uint(env.get("seq")) or not _is_uint(env.get("iat")):
        return "missing or invalid field: seq/iat"
    if _canonical_b64(env.get("nonce"), _NONCE_RE) is None:
        return "invalid nonce encoding"
    if _canonical_b64(env["sig"], _SIG_RE) is None:
        return "invalid sig encoding"
    att = env.get("att")
    if not isinstance(att, dict) or att.get("mode") not in ("producer", "relay"):
        return "missing or invalid field: att"
    sub = att.get("sub")
    if att["mode"] == "relay" and not (isinstance(sub, str) and sub):
        return "relay attestation requires att.sub"
    if "sub" in att and not isinstance(sub, str):
        return "invalid field: att.sub"
    if ("body" in env) == ("enc" in env):
        return "exactly one of body or enc is required"
    if "body" in env and env["body"] is not None and not isinstance(env["body"], dict):
        return "invalid field: body"
    if "enc" in env and not isinstance(env["enc"], dict):
        return "invalid field: enc"
    bix = env.get("bix")
    if "bix" in env and not (isinstance(bix, list) and all(isinstance(x, str) for x in bix)):
        return "invalid field: bix"
    cmt = env.get("cmt")
    if "cmt" in env and not (
        isinstance(cmt, dict)
        and all(isinstance(k, str) and isinstance(v, str) for k, v in cmt.items())
    ):
        return "invalid field: cmt"
    if "prev" in env and not (
        isinstance(env["prev"], str) and _PREV_RE.fullmatch(env["prev"])
    ):
        return "invalid field: prev"
    if "corr" in env and not isinstance(env["corr"], str):
        return "invalid field: corr"
    return None


def verify(
    env: dict, block_tag: str, resolve: Callable[[str], KeyInfo | None]
) -> EnvelopeCheck:
    """Check structure, tag binding, key resolution and signature."""
    problem = _shape_error(env)
    if problem is not None:
        return _malformed(problem)
    try:
        signing_input = _signing_input(env)
    except ValueError as exc:  # CanonicalizationError: NaN, out-of-range integers, ...
        return _malformed(f"not canonicalizable: {exc}")
    except RecursionError:  # nesting json.loads accepts but JCS cannot recurse through
        return _malformed("not canonicalizable: nested too deeply")

    iss, kid, seq, iat = env["iss"], env["kid"], env["seq"], env["iat"]

    def result(verdict: str, reason: str | None = None) -> EnvelopeCheck:
        return EnvelopeCheck(
            verdict, iss, kid, seq, iat, reason, env.get("prev"), env.get("corr")
        )

    if env["tag"] != block_tag:
        return result(verdicts.FORGED, "envelope tag does not match block tag")
    if kid.split("#", 1)[0] != iss:
        return result(verdicts.FORGED, "kid does not belong to iss")
    info = resolve(kid)
    if info is None or info.ed25519_public is None:
        return result(verdicts.FORGED, "signing key not resolvable")
    try:
        Ed25519PublicKey.from_public_bytes(info.ed25519_public).verify(
            _canonical_b64(env["sig"], _SIG_RE), signing_input
        )
    except (InvalidSignature, ValueError):
        return result(verdicts.FORGED, "signature invalid")
    if env["att"]["mode"] == "producer":
        return result(verdicts.PRODUCER_SIGNED)
    return result(verdicts.RELAY_ATTESTED)
