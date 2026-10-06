"""DID resolution for the indexer: a signer's `kid` to its key, as it stood at a given time.

Sources, in order: `offline_docs` (resolve-shaped replies pinned by the operator or a test),
`did:key` (the key is the identifier, nothing to fetch) and the anchor service's resolver
`GET {base_url}/resolve/{did}`, which reads the DID's history on IOTA Rebased and answers
`{doc, version, keys: [{kid, type, publicKeyHex, revokedAtMs}], historyComplete}`. A key that
was replaced in place appears there once per key; `resolve_kid(kid, at_ms)` picks the one in
force throughout the second holding `at_ms` (see `witness_core.bundle.snapshot_keys`):
milestone timestamps have second precision, so a key revoked anywhere in that second counts
as revoked, as in `witness_core.bundle.valid_through_second`.

Answers are cached per DID, including "no such DID": a 404 or any other definitive 4xx. How
long an answer is reused depends on what it is and on the time asked about, so revocations
near the live tip are seen promptly:

- a lookup at or after `fetched - LIVE_WINDOW_MS` (wall clock of the fetch), or for the
  current key (`at_ms` None), reuses an answer at most LIVE_MAX_AGE_S old: a revocation
  published just before or after the fetch must not be missed;
- "no such DID" and documents without `historyComplete: true` live SHORT_TTL_S;
- complete documents asked about an earlier time live `cache_ttl_s`.

A registry that cannot be asked (connection error, timeout, 5xx, 408, 429), or replies with
something that is not an answer about the DID, raises `ResolverUnavailable` and caches
nothing: callers must then decide nothing, rather than treat the signer as unknown.

Without a `base_url` DID resolution is disabled: only `did:key` and `offline_docs` DIDs
resolve, every other DID is unknown (None), never an outage. DIDs longer than
MAX_DID_LENGTH are unknown without asking anyone.
"""

from __future__ import annotations

import copy
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from urllib.parse import quote

import httpx
from witness_core.bundle import second_end_ms, snapshot_resolver
from witness_core.envelope import KeyInfo

DID_RE = re.compile(r"did:(iota|key):[A-Za-z0-9:._%-]+")
MAX_DID_LENGTH = 128  # the anchor service refuses longer ones
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_PUB = b"\xed\x01"  # multicodec ed25519-pub, varint encoded
_KEY_PREFIX = "did:key:"


class ResolverUnavailable(Exception):
    """The registry could not be asked, or did not answer about the DID."""


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


def did_key(ed25519_public: bytes) -> str:
    """The `did:key` identifier of an Ed25519 public key."""
    return _KEY_PREFIX + "z" + _b58encode(_ED25519_PUB + ed25519_public)


def did_key_public(did: str) -> bytes | None:
    """The Ed25519 public key a `did:key` encodes, or None."""
    if not did.startswith(_KEY_PREFIX + "z"):
        return None
    raw = _b58decode(did[len(_KEY_PREFIX) + 1:])
    if raw is None or len(raw) != 34 or not raw.startswith(_ED25519_PUB):
        return None
    return raw[2:]


def _did_key_reply(did: str) -> dict | None:
    """A `did:key` in the anchor's resolve shape: one Ed25519 key, never revoked."""
    public = did_key_public(did)
    if public is None:
        return None
    entry = {"kid": f"{did}#{did[len(_KEY_PREFIX):]}", "type": "Ed25519",
             "publicKeyHex": "0x" + public.hex(), "revokedAtMs": None}
    return {"doc": {"id": did}, "version": None, "keys": [entry], "historyComplete": True}


def _split(kid: object) -> tuple[str, str] | None:
    """(did, kid) with a bare `did:key` expanded to its key fragment; None if unsupported."""
    if not isinstance(kid, str):
        return None
    did, sep, _ = kid.partition("#")
    if len(did) > MAX_DID_LENGTH or not DID_RE.fullmatch(did):
        return None
    if did.startswith(_KEY_PREFIX) and not sep:
        kid = f"{did}#{did[len(_KEY_PREFIX):]}"
    return did, kid


def _is_answer(value: object, did: str) -> bool:
    if not isinstance(value, dict) or not isinstance(value.get("keys"), list):
        return False
    doc = value.get("doc")
    return isinstance(doc, dict) and doc.get("id") == did


def _pick(reply: dict | None, kid: str, at_ms: int | None) -> KeyInfo | None:
    """The key of `kid` valid through the whole second holding `at_ms` (the current key when
    None): never revoked, or revoked at or after the end of that second."""
    if reply is None:
        return None
    at = None if at_ms is None else second_end_ms(at_ms // 1000)
    try:
        return snapshot_resolver(reply)(kid, at)
    except ValueError:
        return None


_MISS = object()
LIVE_WINDOW_MS = 2000  # at_ms this close to the fetch (or later) asks about the live tip
LIVE_MAX_AGE_S = 3.0
SHORT_TTL_S = 5.0  # "no such DID", and documents whose history is incomplete


class _Entry:
    __slots__ = ("fetched", "fetched_wall_ms", "value")

    def __init__(self, fetched: float, fetched_wall_ms: int, value: dict | None) -> None:
        self.fetched = fetched  # monotonic clock when the request was sent
        self.fetched_wall_ms = fetched_wall_ms  # wall clock (epoch ms) at the same moment
        self.value = value


class DidResolver:
    def __init__(
        self,
        base_url: str | None,
        cache_ttl_s: int = 60,
        offline_docs: dict | None = None,
        *,
        timeout_s: float = 2.0,
        cache_size: int = 1024,
        http: httpx.Client | None = None,
        ahttp: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.base_url = base_url.rstrip("/") if base_url else None
        self._ttl = cache_ttl_s
        self._offline = dict(offline_docs or {})
        self._timeout = timeout_s
        self._cache_size = cache_size
        self._http = http
        self._ahttp = ahttp
        self._clock = clock
        self._wall_clock = wall_clock
        self._cache: OrderedDict[str, _Entry] = OrderedDict()
        self._lock = threading.Lock()
        # "ok" / "unreachable" after the last registry exchange; None before any.
        self.status: str | None = None

    # -- public -------------------------------------------------------------------------------

    def resolve_kid(self, kid: str, at_ms: int | None = None) -> KeyInfo | None:
        """The key of `kid` in force at `at_ms` (current key when None).

        None when the DID or the kid does not exist, or the id is not a supported DID.
        Raises ResolverUnavailable when the registry could not answer.
        """
        parts = _split(kid)
        if parts is None:
            return None
        return _pick(self.doc(parts[0], at_ms), parts[1], at_ms)

    async def aresolve_kid(self, kid: str, at_ms: int | None = None) -> KeyInfo | None:
        parts = _split(kid)
        if parts is None:
            return None
        return _pick(await self.adoc(parts[0], at_ms), parts[1], at_ms)

    def doc(self, did: str, at_ms: int | None = None) -> dict | None:
        """The resolve reply for `did` (a DID snapshot), or None if the DID does not exist.
        `at_ms` is the time the caller reads the document at (None: now); it decides whether
        a cached reply is fresh enough."""
        local = self._local(did, at_ms)
        if local is not _MISS:
            return local  # type: ignore[return-value]
        if self._http is None:
            self._http = httpx.Client(timeout=self._timeout)
        sent = self._now()
        try:
            resp = self._http.get(self._url(did), timeout=self._timeout)
        except httpx.HTTPError as exc:
            self.status = "unreachable"
            raise ResolverUnavailable(f"resolver unreachable: {exc}") from exc
        return self._accept(did, resp, sent)

    async def adoc(self, did: str, at_ms: int | None = None) -> dict | None:
        local = self._local(did, at_ms)
        if local is not _MISS:
            return local  # type: ignore[return-value]
        if self._ahttp is None:
            self._ahttp = httpx.AsyncClient(timeout=self._timeout)
        sent = self._now()
        try:
            resp = await self._ahttp.get(self._url(did), timeout=self._timeout)
        except httpx.HTTPError as exc:
            self.status = "unreachable"
            raise ResolverUnavailable(f"resolver unreachable: {exc}") from exc
        return self._accept(did, resp, sent)

    async def aclose(self) -> None:
        if self._ahttp is not None:
            await self._ahttp.aclose()
        if self._http is not None:
            self._http.close()

    # -- internals ----------------------------------------------------------------------------

    def _url(self, did: str) -> str:
        return f"{self.base_url}/resolve/{quote(did, safe='')}"

    def can_resolve(self, did: str) -> bool:
        """Whether `did` can be looked up at all: a well-formed did:key, a pinned document,
        or any supported DID while a registry is configured."""
        if not isinstance(did, str) or len(did) > MAX_DID_LENGTH or not DID_RE.fullmatch(did):
            return False
        return did.startswith(_KEY_PREFIX) or did in self._offline or self.base_url is not None

    def _now(self) -> tuple[float, int]:
        return self._clock(), int(self._wall_clock() * 1000)

    def _fresh(self, entry: _Entry, at_ms: int | None) -> bool:
        """Whether a cached reply may answer a lookup about `at_ms` (None: now)."""
        value = entry.value
        complete = isinstance(value, dict) and value.get("historyComplete") is True
        ttl = self._ttl if complete else min(self._ttl, SHORT_TTL_S)
        if at_ms is None or at_ms >= entry.fetched_wall_ms - LIVE_WINDOW_MS:
            ttl = min(ttl, LIVE_MAX_AGE_S)  # near the live tip: revocations must show up
        return self._clock() - entry.fetched < ttl

    def _local(self, did: str, at_ms: int | None = None) -> object:
        """A reply known without asking the registry, or _MISS."""
        if not isinstance(did, str) or len(did) > MAX_DID_LENGTH or not DID_RE.fullmatch(did):
            return None
        if did in self._offline:
            return copy.deepcopy(self._offline[did])
        if did.startswith(_KEY_PREFIX):
            return _did_key_reply(did)
        with self._lock:
            hit = self._cache.get(did)
            if hit is not None and self._fresh(hit, at_ms):
                self._cache.move_to_end(did)
                return copy.deepcopy(hit.value)
        if self.base_url is None:
            return None  # resolution disabled: the DID is unknown here, not unreachable
        return _MISS

    def _accept(self, did: str, resp: httpx.Response, sent: tuple[float, int]) -> dict | None:
        code = resp.status_code
        if 400 <= code < 500 and code not in (408, 429):
            value = None  # the registry says it has no such DID (or refuses this one for good)
        elif code == 200:
            try:
                value = resp.json()
            except ValueError as exc:
                self.status = "unreachable"
                raise ResolverUnavailable(f"resolver sent no JSON for {did}") from exc
            if not _is_answer(value, did):
                self.status = "unreachable"
                raise ResolverUnavailable(f"resolver reply is not a document of {did}")
        else:
            self.status = "unreachable"
            raise ResolverUnavailable(f"resolver answered HTTP {resp.status_code} for {did}")
        self.status = "ok"
        with self._lock:
            # Stamped with the time the request was sent: the reply may miss anything
            # published while it was in flight.
            self._cache[did] = _Entry(sent[0], sent[1], value)
            self._cache.move_to_end(did)
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)
        return copy.deepcopy(value)
