"""From a tagged-data payload to a message row: decode, classify, judge.

`decode` is pure: it runs the schema registry, keeps only values PostgreSQL can store (no NUL
characters, no lone surrogates, no nesting deeper than MAX_DEPTH) and extracts blind tokens and
the trust score. `resolve_keys` looks up every signing key a milestone needs, before any
database transaction is opened. `judge` gives the single verdict, in this order: envelope
structure and signature, writer policy, replay (an issuer's seq or nonce already used by
another block), key revocation at the milestone's time.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from witness_core import canon, envelope, ids, policy, schema, verdicts
from witness_core.envelope import EnvelopeCheck, KeyInfo
from witness_core.policy import WriterPolicy
from witness_core.schema import Classified

from .store import MessageRow, Store

Classifier = Callable[[str, bytes], Classified]

SIGNED = frozenset({verdicts.PRODUCER_SIGNED, verdicts.RELAY_ATTESTED})
MAX_BLIND_TOKENS = 64
MAX_BLIND_TOKEN_LEN = 256
# Deepest JSON nesting the indexer will canonicalize, verify or store; real aeriOS messages
# are a handful of levels deep. Deeper payloads keep their raw bytes only.
MAX_DEPTH = 64
TOO_DEEP = "nesting too deep"
# Longest DID the resolver is ever asked about (the anchor service's own limit). A longer
# one cannot exist in the registry, so it is unresolvable without asking.
MAX_DID_LENGTH = 128


@runtime_checkable
class KeyResolver(Protocol):
    async def aresolve_kid(self, kid: str, at_ms: int | None) -> KeyInfo | None:
        """The key `kid` names, as it stood at `at_ms` (ms); None if it does not exist.
        Raises when the answer cannot be known (registry unreachable)."""
        ...


class SyncResolver:
    """Adapts a plain `resolve(kid) -> KeyInfo | None` callable to KeyResolver."""

    def __init__(self, resolve: Callable[[str], KeyInfo | None]) -> None:
        self._resolve = resolve

    async def aresolve_kid(self, kid: str, at_ms: int | None) -> KeyInfo | None:
        return self._resolve(kid)


def as_key_resolver(resolve: KeyResolver | Callable[[str], KeyInfo | None]) -> KeyResolver:
    return resolve if isinstance(resolve, KeyResolver) else SyncResolver(resolve)


class ResolverFailed(Exception):
    """A signing key could not be resolved; nothing about the milestone may be decided."""

    def __init__(self, message: str, kid: str) -> None:
        super().__init__(message)
        self.kid = kid


def storable_text(v: Any) -> str | None:
    """`v` if PostgreSQL can hold it in a text column, else None."""
    if not isinstance(v, str) or "\x00" in v:
        return None
    try:
        v.encode("utf-8")
    except UnicodeEncodeError:  # lone surrogate
        return None
    return v


def storable_json(obj: Any) -> bool:
    """True when every string, key and number in `obj` survives a jsonb round trip."""
    stack = [obj]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            if storable_text(v) is None:
                return False
        elif isinstance(v, float):
            if not math.isfinite(v):  # json.loads turns 1e999 into inf
                return False
        elif isinstance(v, dict):
            for k, item in v.items():
                if storable_text(k) is None:
                    return False
                stack.append(item)
        elif isinstance(v, list):
            stack.extend(v)
    return True


def too_deep(obj: Any, limit: int = MAX_DEPTH) -> bool:
    """True when `obj` nests containers more than `limit` levels deep (checked without
    recursion, so any depth is safe to ask about)."""
    stack = [(obj, 1)]
    while stack:
        v, depth = stack.pop()
        children = v.values() if isinstance(v, dict) else v if isinstance(v, list) else None
        if children is None:
            continue
        if depth > limit:
            return True
        stack.extend((c, depth + 1) for c in children if isinstance(c, (dict, list)))
    return False


def decode_tag(tag: bytes) -> str:
    """The tag as text; tags that are not clean UTF-8 are shown as 0x-prefixed hex."""
    try:
        text = tag.decode("utf-8")
    except UnicodeDecodeError:
        return "0x" + tag.hex()
    return text if storable_text(text) is not None else "0x" + tag.hex()


def _canon_hash(obj: Any) -> bytes | None:
    if obj is None:
        return None
    try:
        return canon.canon_hash(obj)
    except Exception:  # noqa: BLE001 - not canonicalizable (lone surrogate, huge int, ...)
        return None


def _prev(v: str | None) -> bytes | None:
    if v is None:
        return None
    try:
        b = ids.from_hex(v)
    except ValueError:
        return None
    return b if len(b) == 32 else None


@dataclass(frozen=True)
class Decoded:
    tag: str
    kind: str
    classified: Classified
    json: Any | None  # what gets stored: the decoded body, None if sealed or not storable
    canon_hash: bytes | None
    blind_tokens: list[str]
    score: float | None  # the trust score, for a well-formed trust.score body
    too_deep: bool = False  # nested beyond MAX_DEPTH: raw bytes only, envelope MALFORMED

    @property
    def envelope(self) -> dict | None:
        return self.classified.envelope


def decode(tag_bytes: bytes, data: bytes, classify: Classifier = schema.classify) -> Decoded:
    tag = decode_tag(tag_bytes)
    c = classify(tag, data)
    kind = c.kind
    if c.envelope is None and not isinstance(c.json, dict):
        kind = schema.UNKNOWN  # binary, scalars, arrays: no kind can apply
    if too_deep(c.envelope if c.envelope is not None else c.json):
        return Decoded(tag, kind, c, None, None, [], None, too_deep=True)
    body = c.json if c.json is None or storable_json(c.json) else None

    tokens: list[str] = []
    bix = c.envelope.get("bix") if c.envelope is not None else None
    if isinstance(bix, list):
        for t in bix[:MAX_BLIND_TOKENS]:
            t = storable_text(t)
            if t and len(t) <= MAX_BLIND_TOKEN_LEN and t not in tokens:
                tokens.append(t)

    score = None
    if kind == "trust.score" and c.schema_ok and c.ie_id and isinstance(c.json, dict):
        score = float(c.json["score"])
    return Decoded(tag, kind, c, body, _canon_hash(c.json), tokens, score)


@dataclass(frozen=True)
class Judgement:
    verdict: str
    check: EnvelopeCheck | None = None
    reason: str | None = None


def signing_kid(d: Decoded) -> str | None:
    """The kid `envelope.verify` will look up for this message, or None when verify settles
    the verdict before that (malformed envelope, tag or kid/iss mismatch, too deep). Found
    by running verify itself with a key lookup that only records the question, so the
    pre-checks are exactly verify's."""
    env = d.envelope
    if env is None or d.too_deep:
        return None
    asked: list[str] = []

    def probe(kid: str) -> None:
        asked.append(kid)

    try:
        envelope.verify(env, d.tag, probe)
    except Exception:  # noqa: BLE001 - judge reports the same envelope as MALFORMED
        return None
    return asked[0] if asked else None


def resolvable(kid: str) -> bool:
    """False for a kid no registry can know (its DID is longer than MAX_DID_LENGTH)."""
    return len(kid.split("#", 1)[0]) <= MAX_DID_LENGTH


async def resolve_keys(resolver: KeyResolver, decoded: Iterable[Decoded],
                       at_ms: int) -> dict[str, KeyInfo | None]:
    """Every key the messages name, as of `at_ms`. Raises ResolverFailed if any lookup
    fails: a key that cannot be looked up must not turn into a FORGED verdict."""
    keys: dict[str, KeyInfo | None] = {}
    for d in decoded:
        kid = signing_kid(d)
        if kid is None or kid in keys:
            continue
        if not resolvable(kid):
            keys[kid] = None  # FORGED "signing key not resolvable", without asking anyone
            continue
        try:
            keys[kid] = await resolver.aresolve_kid(kid, at_ms)
        except Exception as e:
            raise ResolverFailed(f"resolving {kid[:120]}: {type(e).__name__}: {e}"[:500],
                                 kid) from e
    return keys


async def judge(store: Store, pol: WriterPolicy, keys: Mapping[str, KeyInfo | None],
                d: Decoded, block_id: bytes, ms_timestamp: int) -> Judgement:
    """The verdict for one message confirmed by a milestone with timestamp `ms_timestamp` (s).
    `keys` comes from `resolve_keys` for the same milestone."""
    env = d.envelope
    if env is None:
        if d.kind == schema.UNKNOWN and d.tag in schema.KINDS:
            return Judgement(verdicts.MALFORMED, None, "payload is not a JSON object")
        return Judgement(verdicts.UNSIGNED_LEGACY)
    if d.too_deep:
        return Judgement(verdicts.MALFORMED, None, TOO_DEEP)

    def key(kid: str) -> KeyInfo | None:
        if kid not in keys:
            raise LookupError(f"key {kid[:120]} was not resolved before judging")
        return keys[kid]

    try:
        chk = envelope.verify(env, d.tag, key)
    except RecursionError:
        return Judgement(verdicts.MALFORMED, None, TOO_DEEP)
    if chk.verdict not in SIGNED:
        return Judgement(chk.verdict, chk, chk.reason)
    if not policy.allowed(pol, d.tag, chk.iss):
        return Judgement(verdicts.UNAUTHORIZED_WRITER, chk, "issuer not allowed for this tag")

    # White-flag order is not issue order: a lower seq after a higher one is fine. A seq or
    # nonce the issuer already spent in another block is not.
    earlier = await store.seq_used(chk.iss, chk.seq, block_id)
    if earlier is not None:
        return Judgement(verdicts.REPLAY, chk, f"seq {chk.seq} already used by 0x{earlier.hex()}")
    nonce = d.classified.nonce
    if nonce is not None:
        earlier = await store.nonce_used(chk.iss, nonce, block_id)
        if earlier is not None:
            return Judgement(verdicts.REPLAY, chk, f"nonce already used by 0x{earlier.hex()}")

    info = keys.get(chk.kid)
    if info is not None and info.revoked_at_ms is not None \
            and info.revoked_at_ms < ms_timestamp * 1000:
        return Judgement(verdicts.REVOKED_KEY, chk, "key revoked before the milestone")
    return Judgement(chk.verdict, chk)


def message_row(d: Decoded, j: Judgement, *, block_id: bytes, data: bytes, ms_index: int,
                wf_index: int, ts: int) -> MessageRow:
    chk = j.check
    c = d.classified
    return MessageRow(
        block_id=block_id,
        tag=d.tag,
        kind=d.kind,
        data=data,
        json=d.json,
        ie_id=storable_text(c.ie_id),
        canon_hash=d.canon_hash,
        iss=storable_text(chk.iss) if chk else None,
        kid=storable_text(chk.kid) if chk else None,
        seq=chk.seq if chk else None,
        iat=chk.iat if chk else None,
        verdict=j.verdict,
        encrypted=d.envelope is not None and "enc" in d.envelope,
        ms_index=ms_index,
        wf_index=wf_index,
        ts=ts,
        prev=_prev(c.prev),
        corr=storable_text(c.corr),
        nonce=storable_text(c.nonce),
    )
