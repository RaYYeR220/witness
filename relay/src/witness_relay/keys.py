"""Resolve a signer's `kid` to its Ed25519 public key.

Three sources, tried in order: a static file of public JWKs (operator-pinned keys,
optionally marked revoked), `did:key` (self-describing, offline), and the anchor
service's DID resolver (`GET {resolver_url}/resolve/{did}`), cached for a minute.

Only answers about the DID are cached: a document of that DID, a definitive refusal
(DEFINITIVE: "no such DID"), or a document too deep to use (past nesting.MAX_DOC_DEPTH or
the JSON cap), which names no key. Anything else (connection error, timeout, 5xx, 408, 429, an
auth or proxy refusal, a reply that is not a document of the DID) raises KeysUnavailable
and caches nothing, so the request is refused as temporary instead of FORGED.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from collections import OrderedDict
from typing import Any
from urllib.parse import quote

import httpx
from witness_core import nesting
from witness_core.envelope import KeyInfo

log = logging.getLogger(__name__)

# Statuses that answer "no such DID" (or "this id can never resolve"). Any other non-200
# says nothing about the DID: an outage or an auth failure must not read as "no key".
DEFINITIVE = frozenset({400, 404, 410, 414, 422, 431})  # 422: the anchor's "unusable"


class KeysUnavailable(Exception):
    """The DID resolver could not say which key a kid names; decide nothing for now."""


# Only DID methods we can resolve, with a conservative method-specific-id alphabet.
DID_RE = re.compile(r"did:(iota|key):[A-Za-z0-9:._%-]+")
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


def _is_answer(value: object, did: str) -> bool:
    if not isinstance(value, dict) or not isinstance(value.get("keys"), list):
        return False
    doc = value.get("doc")
    return isinstance(doc, dict) and doc.get("id") == did


class KeyResolver:
    def __init__(
        self,
        static: dict[str, KeyInfo] | None = None,
        *,
        resolver_url: str | None = None,
        http: httpx.AsyncClient | None = None,
        cache_ttl_s: float = 60.0,
        cache_size: int = 1024,
    ):
        self._static = dict(static or {})
        self._url = resolver_url.rstrip("/") if resolver_url else None
        self._http = http
        self._ttl = cache_ttl_s
        self._cache_size = cache_size
        self._cache: OrderedDict[str, tuple[float, dict | None]] = OrderedDict()

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
        """The key `kid` names, or None if it names none. Raises KeysUnavailable when the
        DID resolver cannot answer right now."""
        if not isinstance(kid, str):
            return None
        if kid in self._static:
            return self._static[kid]
        did, _, fragment = kid.partition("#")
        if not DID_RE.fullmatch(did):
            return None
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
            self._cache.move_to_end(did)
            return hit[1]
        url = f"{self._url}/resolve/{quote(did, safe='')}"
        try:
            resp = await self._http.get(url, timeout=5.0)
        except httpx.HTTPError as exc:
            log.warning("DID resolution failed for %s: %s", did, exc)
            raise KeysUnavailable(f"DID resolver unreachable ({type(exc).__name__})") from exc
        if resp.status_code in DEFINITIVE:
            value = None  # the registry has no such DID: an answer, cached like a document
        elif resp.status_code == 200:
            try:
                value = nesting.loads(resp.content)
            except nesting.JsonTooDeep:
                value = None  # unusable document: names no key, cached like "no such DID"
            except ValueError as exc:
                raise KeysUnavailable("DID resolver sent no JSON") from exc
            else:
                if not _is_answer(value, did):
                    raise KeysUnavailable("DID resolver reply is not a document of the DID")
                if nesting.value_too_deep(value, nesting.MAX_DOC_DEPTH):
                    value = None  # unusable document, as above
        else:
            log.warning("DID resolution failed for %s: HTTP %s", did, resp.status_code)
            raise KeysUnavailable(f"DID resolver answered HTTP {resp.status_code}")
        self._cache[did] = (now, value)
        self._cache.move_to_end(did)
        while len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)
        return value

    @staticmethod
    def _from_document(kid: str, resolution: dict | None) -> KeyInfo | None:
        """Pick the Ed25519 key for `kid` from an anchor `/resolve` reply.

        The reply lists every key the DID has had (`keys`), so a kid that was replaced
        appears twice. Prefer the entry that is valid now; otherwise the one revoked last.
        """
        if not isinstance(resolution, dict):
            return None
        fragment = "#" + kid.partition("#")[2]
        now = int(time.time() * 1000)
        found: list[tuple[bytes, int | None]] = []
        for entry in resolution.get("keys") or []:
            if not isinstance(entry, dict) or entry.get("kid") not in (kid, fragment):
                continue
            if entry.get("type") != "Ed25519":
                continue
            try:
                pub = bytes.fromhex(entry.get("publicKeyHex") or "")
            except ValueError:
                continue
            if len(pub) != 32:
                continue
            at = entry.get("revokedAtMs")
            if at is not None and (not isinstance(at, int) or isinstance(at, bool)):
                continue  # malformed revocation time: fail closed, ignore the entry
            found.append((pub, at))
        if not found:
            return None
        live = [f for f in found if f[1] is None or f[1] > now]
        # several live entries for one kid: the resolver lists oldest first, take the last
        pub, revoked = live[-1] if live else max(found, key=lambda f: f[1] or 0)
        return KeyInfo(kid, pub, None, revoked)
