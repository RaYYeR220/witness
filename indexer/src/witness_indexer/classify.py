"""From a tagged-data payload to a message row: decode, classify, judge.

`decode` is pure: it runs the schema registry, keeps only values PostgreSQL can store (no NUL
characters, no lone surrogates) and extracts blind tokens and the trust score. `judge` gives
the single verdict, in this order: envelope structure and signature, writer policy, replay
against what the issuer already wrote, key revocation at the milestone's time.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from witness_core import canon, envelope, ids, policy, schema, verdicts
from witness_core.envelope import EnvelopeCheck, KeyInfo
from witness_core.policy import WriterPolicy
from witness_core.schema import Classified

from .store import MessageRow, Store

Classifier = Callable[[str, bytes], Classified]
Resolver = Callable[[str], KeyInfo | None]

SIGNED = frozenset({verdicts.PRODUCER_SIGNED, verdicts.RELAY_ATTESTED})
MAX_BLIND_TOKENS = 64
MAX_BLIND_TOKEN_LEN = 256


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

    @property
    def envelope(self) -> dict | None:
        return self.classified.envelope


def decode(tag_bytes: bytes, data: bytes, classify: Classifier = schema.classify) -> Decoded:
    tag = decode_tag(tag_bytes)
    c = classify(tag, data)
    kind = c.kind
    if c.envelope is None and not isinstance(c.json, dict):
        kind = schema.UNKNOWN  # binary, scalars, arrays: no kind can apply
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


async def judge(store: Store, pol: WriterPolicy, resolve: Resolver, d: Decoded,
                block_id: bytes, ms_timestamp: int) -> Judgement:
    """The verdict for one message confirmed by a milestone with timestamp `ms_timestamp` (s).

    Exceptions from `resolve` propagate: a resolver outage must not be recorded as FORGED.
    """
    env = d.envelope
    if env is None:
        if d.kind == schema.UNKNOWN and d.tag in schema.KINDS:
            return Judgement(verdicts.MALFORMED, None, "payload is not a JSON object")
        return Judgement(verdicts.UNSIGNED_LEGACY)

    chk = envelope.verify(env, d.tag, resolve)
    if chk.verdict not in SIGNED:
        return Judgement(chk.verdict, chk, chk.reason)
    if not policy.allowed(pol, d.tag, chk.iss):
        return Judgement(verdicts.UNAUTHORIZED_WRITER, chk, "issuer not allowed for this tag")

    last_seq, nonces = await store.issuer_state(chk.iss, exclude_block_id=block_id)
    if last_seq is not None and chk.seq <= last_seq:
        return Judgement(verdicts.REPLAY, chk, f"seq {chk.seq} <= last seen {last_seq}")
    if d.classified.nonce is not None and d.classified.nonce in nonces:
        return Judgement(verdicts.REPLAY, chk, "nonce already used by this issuer")

    info = resolve(chk.kid)
    if info is not None and info.revoked_at_ms is not None \
            and ms_timestamp * 1000 >= info.revoked_at_ms:
        return Judgement(verdicts.REVOKED_KEY, chk, "key revoked before confirmation")
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
