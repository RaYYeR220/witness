"""Resolve a signer's `kid` to its Ed25519 public key.

Three sources, tried in order: a static file of public JWKs (operator-pinned keys,
optionally marked revoked), `did:key` (self-describing, offline), and the anchor
service's DID resolver (`GET {resolver_url}/resolve/{did}`), cached for a minute.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any

import httpx
from witness_core.envelope import KeyInfo

log = logging.getLogger(__name__)

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_PUB = b"\xed\x01"  # multicodec ed25519-pub, varint encoded


def _b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def _b58decode(s: str) -> bytes | None:
    n = 0
    for ch in s:
        i = _B58.find(ch)
        if i < 0:
            return None
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


def _b64u_decode(s: Any) -> bytes | None:
    if not isinstance(s, str):
        return None
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except ValueError:
        return None


def did_key(ed25519_public: bytes) -> str:
    """The `did:key` identifier of an Ed25519 public key."""
    return "did:key:z" + _b58encode(_ED25519_PUB + ed25519_public)


def did_key_public(did: str) -> bytes | None:
    """Ed25519 public key encoded in a `did:key`, or None."""
    if not did.startswith("did:key:z"):
        return None
    raw = _b58decode(did[len("did:key:z") :])
    if raw is None or len(raw) != 34 or not raw.startswith(_ED25519_PUB):
        return None
    return raw[2:]


def _jwk_ed25519(jwk: Any) -> bytes | None:
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        return None
    raw = _b64u_decode(jwk.get("x"))
    return raw if raw is not None and len(raw) == 32 else None


def _load_static(path: str) -> dict[str, KeyInfo]:
    with open(path, encoding="utf-8") as f:
        entries = json.load(f)
    if isinstance(entries, dict):
        entries = entries.get("keys", [])
    out: dict[str, KeyInfo] = {}
    for jwk in entries:
        pub = _jwk_ed25519(jwk)
        kid = jwk.get("kid") if isinstance(jwk, dict) else None
        if pub is None or not isinstance(kid, str):
            continue
        revoked = jwk.get("revokedAtMs")
        out[kid] = KeyInfo(kid, pub, None, revoked if isinstance(revoked, int) else None)
    return out


class KeyResolver:
    def __init__(
        self,
        static: dict[str, KeyInfo] | None = None,
        *,
        resolver_url: str | None = None,
        http: httpx.AsyncClient | None = None,
        cache_ttl_s: float = 60.0,
    ):
        self._static = dict(static or {})
        self._url = resolver_url.rstrip("/") if resolver_url else None
        self._http = http
        self._ttl = cache_ttl_s
        self._cache: dict[str, tuple[float, dict | None]] = {}

    @classmethod
    def from_files(
        cls,
        trusted_keys_path: str | None,
        *,
        resolver_url: str | None = None,
        http: httpx.AsyncClient | None = None,
    ) -> KeyResolver:
        static = _load_static(trusted_keys_path) if trusted_keys_path else {}
        return cls(static, resolver_url=resolver_url, http=http)

    async def resolve(self, kid: str) -> KeyInfo | None:
        if not isinstance(kid, str):
            return None
        if kid in self._static:
            return self._static[kid]
        did, _, fragment = kid.partition("#")
        if did.startswith("did:key:"):
            pub = did_key_public(did)
            if pub is None or fragment not in ("", did[len("did:key:") :]):
                return None
            return KeyInfo(kid, pub, None, None)
        if self._url and self._http is not None:
            return self._from_document(kid, await self._resolution(did))
        return None

    async def _resolution(self, did: str) -> dict | None:
        hit = self._cache.get(did)
        now = time.monotonic()
        if hit is not None and now - hit[0] < self._ttl:
            return hit[1]
        try:
            resp = await self._http.get(f"{self._url}/resolve/{did}", timeout=5.0)
            result = resp.json() if resp.status_code == 200 else None
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("DID resolution failed for %s: %s", did, exc)
            return None  # not cached: retry on the next message
        self._cache[did] = (now, result if isinstance(result, dict) else None)
        return self._cache[did][1]

    @staticmethod
    def _from_document(kid: str, resolution: dict | None) -> KeyInfo | None:
        if not resolution:
            return None
        doc = resolution.get("doc") or {}
        fragment = "#" + kid.partition("#")[2]
        pub = None
        for method in doc.get("verificationMethod") or []:
            if isinstance(method, dict) and method.get("id") in (kid, fragment):
                pub = _jwk_ed25519(method.get("publicKeyJwk"))
                break
        if pub is None:
            return None
        revoked = None
        for entry in resolution.get("revokedMethods") or []:
            if isinstance(entry, dict) and entry.get("kid") in (kid, fragment):
                at = entry.get("revokedAtMs")
                revoked = at if isinstance(at, int) else 0
        return KeyInfo(kid, pub, None, revoked)
