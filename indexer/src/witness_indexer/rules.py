"""Integrity rules: per-message verdicts and cross-source observations turned into alerts.

Per message (`on_message`, called once the verdict pipeline has stored the row):

- R1 FORGED, R2 UNAUTHORIZED_WRITER, R3 REPLAY, R9 MALFORMED, R10 REVOKED_KEY: the
  pipeline's verdict, with evidence saying why;
- R4 UNSIGNED: an unsigned message on a tag whose writer policy requires signatures;
- R6 UNKNOWN_IE: a message about an Infrastructure Element that Orion does not know;
- R7 ANOMALY: a trust score jump beyond `jump_threshold` with no trustworthy security event
  for the IE (self-orchestrator error, self-security alert) shortly before it;
- R12 CLOCK_SKEW: the signer's `iat` far from the milestone timestamp;
- R15 CHAIN_GAP: the envelope's `prev` is not the issuer's last seen block;
- R16 CHAIN_FORK: two messages of one issuer continue from the same `prev`.

Periodic (`periodic(now_ms=...)`):

- R5 DRIFT: Orion's `trustScore` differs from the latest ledger score by more than
  `drift_epsilon`, or cannot be read at all, for longer than `drift_grace_s`;
- R8 STALE: no ledger score for an IE within `stale_factor` x `score_interval_s`;
- R11 ANCHOR_MISMATCH: the milestone ids stored for an anchored window no longer hash to the
  `msRoot` recorded on IOTA Rebased (fetched from the anchor service, never taken from the
  private-Tangle mirror), or the `witness.anchor` mirror disagrees with Rebased. Every anchor
  is visited (unverified ones first, the rest by a rotating cursor); one that stays
  unverifiable past `anchor_unverifiable_grace_s` raises ANCHOR_UNVERIFIABLE;
- R14 SHADOW: a confirmed tagged-data block that no submission from the Messages API names,
  `shadow_grace_s` after confirmation (tags in `shadow_exempt_tags` are never relayed),
  judged from a baseline that is fixed once and persisted.

`rescan` takes the confirmed tagged-data block ids read back from the Tangle (INX or REST) and
reports the ones absent from the database as MISSING_IN_DB. That is what catches a wiped
parallel database, which leaves nothing for the validator to re-verify.

R13 ORPHANED, R17 CONTENT_MISMATCH and R18 DB_TAMPER (and NOT_FOUND) are raised by the
validator, which holds the submissions and the node answers they rest on; they are not
repeated here.

Rules never change a verdict and never conclude from a service they could not ask: with Orion
unreachable there is no DRIFT or UNKNOWN_IE, with the anchor service unreachable no
ANCHOR_MISMATCH, and an unreachable DID resolver only leaves evidence incomplete. Hostile
content cannot stop them either: every rule runs on its own (inside a savepoint when the
caller holds a transaction), a failing rule is logged and reported, and evidence is
sanitised before it is stored. What was last observed is in `Store.stats()`: `orion`,
`resolver(rules)` ("ok" | "unreachable", the rules' own lookups; `resolver` belongs to the
indexer), `anchor` ("ok" | "pending" | "unverifiable" |
"unreachable"), `shadow` ("ok" | "no-baseline"), `ledger` ("ok" | "stalled" | "empty") and
`rules` ("ok" | "error").

Alerts are stored (deduplicated by rule, block, IE and dedupe key) and emitted as `alert`
events; the lists returned hold only alerts that were new.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import logging
import math
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any, ClassVar

from witness_core import checkpoint, envelope, merkle, nesting, schema
from witness_core import verdicts as V
from witness_core.bundle import snapshot_keys
from witness_core.envelope import KeyInfo
from witness_core.ids import NON_CANONICAL_DID, is_canonical_did, to_hex
from witness_core.policy import TagRule, WriterPolicy

from . import events
from .anchor_client import AnchorClient, AnchorUnavailable
from .classify import TOO_DEEP
from .orion import IE, IE_URN, MISSING, OrionClient, OrionUnavailable
from .resolver import DidResolver, ResolverUnavailable
from .store import Alert, MessageRow, Store

__all__ = ["SEVERITY", "Alert", "RulesConfig", "RulesEngine"]

log = logging.getLogger(__name__)

SEVERITY: dict[str, str] = {
    "FORGED": "critical",
    "ANCHOR_MISMATCH": "critical",
    "MISSING_IN_DB": "critical",
    "REPLAY": "high",
    "UNAUTHORIZED_WRITER": "high",
    "REVOKED_KEY": "high",
    "CHAIN_FORK": "high",
    "SHADOW": "high",
    "DRIFT": "medium",
    "ANOMALY": "medium",
    "CHAIN_GAP": "medium",
    "UNSIGNED": "medium",
    "STALE": "low",
    "UNKNOWN_IE": "low",
    "CLOCK_SKEW": "low",
    "MALFORMED": "low",
    "ANCHOR_UNVERIFIABLE": "low",
}

# Verdicts that prove the issuer: the only messages chain, replay and skew rules look at.
PROVEN = (V.PRODUCER_SIGNED, V.RELAY_ATTESTED)
SCORE_KIND = "trust.score"
# An IE missing from the cached Orion list triggers a refresh, at most this often.
ORION_MISS_REFRESH_S = 5.0
# Evidence limits: text is cut, deep or long structures are summarised.
TEXT_MAX = 512
DEPTH_MAX = 8
ITEMS_MAX = 64
# Persistent rule state (Store.get_rule_state / set_rule_state).
ANCHOR_CURSOR = "r11.cursor"
SHADOW_BASELINE = "r14.baseline_ms"


@dataclass(frozen=True)
class RulesConfig:
    drift_epsilon: float = 0.01
    drift_grace_s: int = 150
    jump_threshold: float = 0.3
    stale_factor: float = 2.0
    score_interval_s: int = 60
    clock_skew_s: int = 300
    corroboration_window_s: int = 300
    security_tags: frozenset[str] = frozenset({"self-orchestrator", "self-security"})
    shadow_grace_s: int = 30
    shadow_exempt_tags: frozenset[str] = frozenset()
    # Blocks confirmed before this are never SHADOW. Unset: the first submission ever seen,
    # fixed and persisted the first time it is known.
    shadow_since_ms: int | None = None
    orion_ttl_s: float = 30.0
    # R11 looks at up to this many unverified anchors plus this many by rotation per pass.
    anchor_batch: int = 50
    anchor_unverifiable_grace_s: int = 600
    # `rules: error` stays up this long after the last rule failure.
    error_hold_s: int = 600
    batch: int = 500


@dataclass
class _Episode:
    since_ms: int
    alerted: bool = False


def _hex(b: bytes | None) -> str | None:
    return None if b is None else to_hex(bytes(b))


def _clean_text(s: str) -> str:
    """Text PostgreSQL accepts in jsonb/text: lone surrogates and NUL escaped, length cut."""
    s = s.encode("utf-8", "backslashreplace").decode("utf-8").replace("\x00", "\\x00")
    return s if len(s) <= TEXT_MAX else s[:TEXT_MAX - 3] + "..."


def _clean(v: Any, depth: int = 0) -> Any:
    """A JSON-safe, storable copy of an evidence value."""
    if isinstance(v, str):
        return _clean_text(v)
    if v is None or isinstance(v, bool | int):
        return v
    if isinstance(v, float):
        return v if math.isfinite(v) else str(v)
    if isinstance(v, bytes | bytearray | memoryview):
        return to_hex(bytes(v))
    if depth >= DEPTH_MAX:
        return "<nested value omitted>"
    if isinstance(v, dict):
        items = list(v.items())
        out = {_clean_text(str(k)): _clean(x, depth + 1) for k, x in items[:ITEMS_MAX]}
        if len(items) > ITEMS_MAX:
            out["..."] = f"{len(items) - ITEMS_MAX} more entries"
        return out
    if isinstance(v, list | tuple):
        seq = [_clean(x, depth + 1) for x in v[:ITEMS_MAX]]
        if len(v) > ITEMS_MAX:
            seq.append(f"... {len(v) - ITEMS_MAX} more items")
        return seq
    return _clean_text(repr(v))


def _cleaned(a: Alert) -> Alert:
    return dataclasses.replace(
        a, evidence=_clean(a.evidence),
        ie_id=None if a.ie_id is None else _clean_text(a.ie_id),
        dedupe_key=None if a.dedupe_key is None else _clean_text(a.dedupe_key))


def _json(data: bytes | None) -> Any:
    def reject(token: str) -> Any:
        raise ValueError(f"non-finite number {token}")

    if data is None:
        return None
    try:
        return nesting.loads(bytes(data).decode("utf-8"), parse_constant=reject)
    except ValueError:  # not UTF-8, not JSON, or nested past the shared cap
        return None


def _over_cap(data: bytes | None) -> bool:
    try:
        return data is not None and nesting.text_too_deep(bytes(data).decode("utf-8"))
    except UnicodeDecodeError:
        return False


def _envelope_of(row: MessageRow) -> dict | None:
    obj = _json(row.data)
    return obj if envelope.is_envelope(obj) else None


def _score(v: Any) -> float | None:
    if isinstance(v, bool) or not isinstance(v, int | float):
        return None
    v = float(v)
    return v if math.isfinite(v) and 0 <= v <= 1 else None


def _signed_by(env: dict, tag: str, key: KeyInfo) -> bool:
    try:
        return envelope.verify(env, tag, lambda _kid: key).verdict in PROVEN
    except Exception:  # noqa: BLE001 - a hostile envelope only fails to verify
        return False


def _orion_value(raw: Any) -> str:
    if raw is MISSING:
        return "missing"
    try:
        return json.dumps(raw, default=repr)[:200]
    except (ValueError, RecursionError):
        return repr(raw)[:200]


def _alert_event(a: Alert) -> dict:
    return {"rule": a.rule, "severity": a.severity, "blockId": _hex(a.block_id),
            "ieId": a.ie_id, "ts": a.ts, "dedupeKey": a.dedupe_key}


def _record_problem(rec: dict, seq: int) -> str | None:
    """Why an anchor reply cannot serve as the on-chain reference, or None."""
    cp = rec.get("checkpoint")
    problem = checkpoint.shape_error(cp)
    if problem is not None:
        return f"malformed checkpoint: {problem}"
    try:
        digest = checkpoint.hash(cp)
    except ValueError:
        return "checkpoint cannot be canonicalized"
    claimed = rec.get("checkpointHash")
    if claimed is not None and (not isinstance(claimed, str) or claimed.lower() != to_hex(digest)):
        return "checkpointHash does not match the checkpoint"
    if rec.get("seq") is not None and rec["seq"] != seq:
        return f"reply is about checkpoint {rec['seq']!r}"
    return None


class RulesEngine:
    def __init__(self, store: Store, orion: OrionClient | None, resolver: DidResolver | None,
                 policy: WriterPolicy, cfg: RulesConfig | None = None, *,
                 anchor: AnchorClient | None = None,
                 now_ms: Callable[[], int] | None = None) -> None:
        """`anchor` defaults to the resolver's base URL: the anchor service serves both
        `/resolve` and `/checkpoints`. Without either, R11 is off."""
        self.store = store
        self.orion = orion
        self.resolver = resolver
        self.policy = policy
        self.cfg = cfg or RulesConfig()
        if anchor is None and resolver is not None and resolver.base_url:
            anchor = AnchorClient(resolver.base_url)
        self.anchor = anchor
        self._now = now_ms or (lambda: int(time.time() * 1000))
        self._ies: frozenset[str] | None = None
        self._ies_at = -math.inf
        self._drift: dict[str, _Episode] = {}
        self._onchain: dict[int, dict] = {}
        self._status: dict[str, str] = {}
        self._shadow_since: int | None = None
        self._last_error_ms: int | None = None

    # -- entry points -------------------------------------------------------------------------

    async def on_message(self, row: MessageRow) -> list[Alert]:
        """Rules for one stored message; returns the alerts that were new."""
        now = self._now()
        found: list[Alert] = []

        async def run(name: str, fn: Callable[..., Any], *args: Any) -> None:
            alert = await self._guard(name, fn, *args)
            if alert is not None:
                found.append(alert)

        explain = self._EXPLAIN.get(row.verdict or "")
        if explain is not None:
            await run(str(row.verdict), explain, self, row, now)
        if row.verdict == V.UNSIGNED_LEGACY:
            await run("UNSIGNED", self._unsigned, row, now)
        if self._content_trusted(row):
            await run("UNKNOWN_IE", self._unknown_ie, row, now)
            await run("ANOMALY", self._anomaly, row, now)
        if row.verdict in PROVEN:
            await run("CLOCK_SKEW", self._clock_skew, row, now)
            await run("CHAIN", self._chain, row, now)
        return await self._commit(found)

    async def periodic(self, *, now_ms: int) -> list[Alert]:
        """Time-based and cross-source rules (R5, R8, R11, R14) as of `now_ms` (epoch ms);
        returns the alerts that were new."""
        found: list[Alert] = []
        for name, fn in (("DRIFT", self._drift_rule), ("STALE", self._stale),
                         ("ANCHOR", self._anchors), ("SHADOW", self._shadow)):
            found += await self._guard(name, fn, now_ms) or []
        new = await self._commit(found)
        last = self._last_error_ms
        if last is None or self._now() - last > self.cfg.error_hold_s * 1000:
            await self._set_status("rules", "ok")
        return new

    async def rescan(self, confirmed_block_ids: Iterable[bytes], *,
                     now_ms: int | None = None) -> list[Alert]:
        """MISSING_IN_DB for every confirmed tagged-data block id the database lacks.

        The ids must come from the Tangle (INX or the node's REST API) and belong to
        milestones the indexer has already processed; a block the indexer simply has not
        reached yet would otherwise read as deleted.
        """
        now = self._now() if now_ms is None else now_ms
        ids = list(dict.fromkeys(bytes(b) for b in confirmed_block_ids))
        found: list[Alert] = []
        for i in range(0, len(ids), self.cfg.batch):
            for bid in await self.store.missing_messages(ids[i:i + self.cfg.batch]):
                evidence = {
                    "blockId": to_hex(bid), "source": "Tangle re-scan",
                    "reason": "a confirmed tagged-data block is absent from the parallel "
                              "database (rows deleted, or the database was replaced)",
                }
                found.append(Alert("MISSING_IN_DB", SEVERITY["MISSING_IN_DB"], bid, None,
                                   evidence, now))
        return await self._commit(found)

    # -- plumbing -----------------------------------------------------------------------------

    async def _guard(self, name: str, fn: Callable[..., Any], *args: Any) -> Any:
        """Run one rule; a failure is logged and reported (`rules: error`) and yields None,
        and inside a caller's transaction it only rolls back the rule's own statements."""
        try:
            async with self.store.savepoint():
                result = fn(*args)
                if inspect.isawaitable(result):
                    result = await result
                return result
        except Exception as exc:  # one rule must never stop the others
            log.exception("rule %s failed", name)
            await self._rule_failed(name, exc)
            return None

    async def _rule_failed(self, name: str, exc: Exception) -> None:
        self._last_error_ms = self._now()
        await self.store.set_service_status(
            "rules", "error", detail=_clean_text(f"{name}: {type(exc).__name__}: {exc}"),
            at_ms=self._last_error_ms)
        self._status["rules"] = "error"

    async def _commit(self, alerts: list[Alert]) -> list[Alert]:
        new: list[Alert] = []
        for a in map(_cleaned, alerts):
            try:
                async with self.store.transaction(), self.store.savepoint():
                    if not await self.store.put_alert(a):
                        continue
                    if a.rule == "SHADOW" and a.block_id is not None:
                        detail = {"cause": "SHADOW", "graceS": self.cfg.shadow_grace_s}
                        await self.store.set_lifecycle(block_id=a.block_id, sub_id=None,
                                                       status="SHADOW", at_ms=a.ts,
                                                       detail=detail)
                        await self.store.emit(events.LIFECYCLE, {
                            "blockId": _hex(a.block_id), "subId": None, "status": "SHADOW",
                            "atMs": a.ts, "detail": detail})
                    await self.store.emit(events.ALERT, _alert_event(a))
            except Exception as exc:  # one alert must not lose the others
                log.exception("storing %s alert failed", a.rule)
                await self._rule_failed(f"store {a.rule}", exc)
                continue
            new.append(a)
        return new

    async def _set_status(self, name: str, status: str, detail: str | None = None) -> None:
        if self._status.get(name) == status:
            return
        await self.store.set_service_status(
            name, status, detail=None if detail is None else _clean_text(detail),
            at_ms=self._now())
        self._status[name] = status

    def _rule_for(self, tag: str | None) -> TagRule:
        return self.policy.tags.get(tag, self.policy.default) if tag else self.policy.default

    def _requires_signature(self, tag: str | None) -> bool:
        """Same reading as the relay's policy gate: unsigned writes are refused."""
        rule = self._rule_for(tag)
        return rule.require_signature and not rule.legacy_grace

    def _content_trusted(self, row: MessageRow) -> bool:
        if row.verdict in PROVEN:
            return True
        return row.verdict == V.UNSIGNED_LEGACY and not self._requires_signature(row.tag)

    def _score_verdicts(self) -> list[str]:
        if self._requires_signature(SCORE_KIND):
            return list(PROVEN)
        return [*PROVEN, V.UNSIGNED_LEGACY]

    def _alert(self, rule: str, row: MessageRow, evidence: dict, now: int) -> Alert:
        return Alert(rule, SEVERITY[rule], row.block_id, row.ie_id, evidence, now)

    async def _did_doc(self, did: str) -> tuple[dict | None, str | None]:
        """(resolve reply, None) or (None, why it could not be fetched)."""
        if self.resolver is None:
            return None, "no DID resolver configured"
        if not self.resolver.can_resolve(did):
            if self.resolver.base_url is None:
                return None, f"DID resolution disabled ({did})"
            return None, f"{did} is not a resolvable DID (unsupported or too long)"
        try:
            doc = await self.resolver.adoc(did)
        except ResolverUnavailable as exc:
            await self._set_status("resolver(rules)", "unreachable", str(exc))
            return None, f"DID resolver unavailable ({exc})"
        await self._set_status("resolver(rules)", "ok")
        return doc, None

    # -- R1 R2 R3 R9 R10: verdicts explained ----------------------------------------------------

    async def _forged(self, row: MessageRow, now: int) -> Alert:
        env = _envelope_of(row)
        evidence = {"tag": row.tag, "iss": row.iss, "kid": row.kid,
                    "reason": await self._forgery_reason(row, env)}
        return self._alert("FORGED", row, evidence, now)

    async def _forgery_reason(self, row: MessageRow, env: dict | None) -> str:
        if env is None:
            return "not a readable envelope"
        offline = envelope.verify(env, row.tag or "", lambda _kid: None)
        if offline.verdict != V.FORGED or offline.reason != "signing key not resolvable":
            return offline.reason or offline.verdict  # tag or kid/iss binding broken
        kid, iss = env["kid"], env["iss"]
        if not is_canonical_did(iss):
            return f"{NON_CANONICAL_DID}: {iss}"
        doc, unavailable = await self._did_doc(iss)
        if unavailable is not None:
            return f"signature not re-checked: {unavailable}"
        try:
            keys = snapshot_keys(doc).get(kid, []) if doc is not None else []
        except ValueError:
            keys = []
        signing = [k for k in keys if k.ed25519_public is not None]
        if not signing:
            return f"{kid} is not a key published by {iss}"
        if any(_signed_by(env, row.tag or "", k) for k in signing):
            return (f"signature verifies against a key {kid} has had, but not the one in "
                    f"force when the block was confirmed")
        return f"signature does not verify against any key published as {kid}"

    async def _unauthorized(self, row: MessageRow, now: int) -> Alert:
        rule = self._rule_for(row.tag)
        evidence = {"iss": row.iss, "tag": row.tag, "allowed": list(rule.allowed),
                    "policyVersion": self.policy.version,
                    "reason": f"{row.iss} is not an allowed writer of {row.tag!r}"}
        return self._alert("UNAUTHORIZED_WRITER", row, evidence, now)

    async def _replay(self, row: MessageRow, now: int) -> Alert:
        reasons: list[str] = []
        earlier: list[str] = []
        if row.iss is not None:
            # The indexer's rule: a seq or nonce this issuer already spent in another block.
            if row.seq is not None:
                used = await self.store.seq_used(row.iss, row.seq, row.block_id)
                if used is not None:
                    earlier.append(to_hex(used))
                    reasons.append(f"seq {row.seq} already used by block {to_hex(used)}")
            if row.nonce is not None:
                used = await self.store.nonce_used(row.iss, row.nonce, row.block_id)
                if used is not None:
                    earlier.append(to_hex(used))
                    reasons.append(f"nonce already used by block {to_hex(used)}")
        if row.canon_hash is not None:
            for m in await self.store.lookup_canon(row.canon_hash):
                if bytes(m["block_id"]) != row.block_id:
                    reasons.append(f"identical envelope already recorded in block "
                                   f"{to_hex(bytes(m['block_id']))}")
                    break
        evidence = {"iss": row.iss, "seq": row.seq, "nonce": row.nonce,
                    "earlierBlocks": list(dict.fromkeys(earlier)),
                    "reasons": reasons or ["flagged as a replay when indexed"]}
        return self._alert("REPLAY", row, evidence, now)

    async def _malformed(self, row: MessageRow, now: int) -> Alert:
        obj = _json(row.data)
        if obj is None:
            reason = TOO_DEEP if _over_cap(row.data) else "data is not JSON"
        elif envelope.is_envelope(obj):
            check = envelope.verify(obj, row.tag or "", lambda _kid: None)
            problem = schema.body_problem(row.tag or "", obj) or (
                f"body does not match the {row.kind} schema")
            reason = check.reason if check.verdict == V.MALFORMED else f"envelope {problem}"
        else:
            reason = f"body does not match the {row.kind} schema"
        evidence: dict[str, Any] = {"tag": row.tag, "kind": row.kind, "reason": reason}
        if row.iss is not None:
            # Only a verified signature puts an issuer on the row (classify.judge): the
            # envelope itself is sound and signed, its body is what breaks the schema.
            att = obj.get("att") if isinstance(obj, dict) else None
            evidence["signature"] = {
                "verified": True, "iss": row.iss, "kid": row.kid, "seq": row.seq,
                "mode": att.get("mode") if isinstance(att, dict) else None}
        return self._alert("MALFORMED", row, evidence, now)

    async def _revoked(self, row: MessageRow, now: int) -> Alert:
        included = row.ts * 1000 if row.ts > 0 else None
        evidence: dict[str, Any] = {"iss": row.iss, "kid": row.kid, "iatMs": row.iat,
                                    "includedAtMs": included, "revokedAtMs": None}
        env = _envelope_of(row)
        iss, kid = (env.get("iss"), env.get("kid")) if env is not None else (None, None)
        if not (isinstance(iss, str) and isinstance(kid, str)):
            evidence["note"] = "revocation time unknown: no readable iss/kid in the envelope"
        else:
            doc, unavailable = await self._did_doc(iss)
            if unavailable is not None:
                evidence["note"] = f"revocation time unknown: {unavailable}"
            else:
                try:
                    keys = snapshot_keys(doc).get(kid, []) if doc is not None else []
                except ValueError:
                    keys = []
                for k in keys:
                    if k.ed25519_public is not None and _signed_by(env, row.tag or "", k):
                        evidence["revokedAtMs"] = k.revoked_at_ms
                        break
        # Same rule as the verdict (classify.judge): milestone time has second precision.
        evidence["reason"] = ("signed with a key that was revoked before or within the "
                              "milestone's second")
        return self._alert("REVOKED_KEY", row, evidence, now)

    _EXPLAIN: ClassVar[dict[str, Callable[..., Awaitable[Alert]]]] = {
        V.FORGED: _forged,
        V.UNAUTHORIZED_WRITER: _unauthorized,
        V.REPLAY: _replay,
        V.MALFORMED: _malformed,
        V.REVOKED_KEY: _revoked,
    }

    # -- R4 R6 R7 R12 R15 R16 -----------------------------------------------------------------

    def _unsigned(self, row: MessageRow, now: int) -> Alert | None:
        if not self._requires_signature(row.tag):
            return None
        evidence = {"tag": row.tag, "policyVersion": self.policy.version,
                    "reason": f"writer policy v{self.policy.version} requires signed messages "
                              f"on {row.tag!r}"}
        return self._alert("UNSIGNED", row, evidence, now)

    async def _fetch_ies(self) -> list[IE] | None:
        """Orion's IE entities, or None (status `orion: unreachable`) if it cannot be asked."""
        if self.orion is None:
            return None
        try:
            ies = await self.orion.ie_entities()
        except OrionUnavailable as exc:
            self._ies, self._ies_at = None, time.monotonic()
            await self._set_status("orion", "unreachable", str(exc))
            return None
        self._ies, self._ies_at = frozenset(i.ie_id for i in ies), time.monotonic()
        await self._set_status("orion", "ok")
        return ies

    async def _known_ies(self, ie_id: str) -> frozenset[str] | None:
        age = time.monotonic() - self._ies_at
        missing = self._ies is not None and ie_id not in self._ies
        if age > self.cfg.orion_ttl_s or (missing and age > ORION_MISS_REFRESH_S):
            await self._fetch_ies()
        return self._ies

    async def _unknown_ie(self, row: MessageRow, now: int) -> Alert | None:
        if row.ie_id is None or self.orion is None:
            return None
        known = await self._known_ies(row.ie_id)
        if known is None or row.ie_id in known:
            return None
        if await self.store.has_alert("UNKNOWN_IE", ie_id=row.ie_id):
            return None  # once per IE
        evidence = {"ieId": row.ie_id, "entityId": IE_URN + row.ie_id, "tag": row.tag,
                    "reason": "Orion has no InfrastructureElement with this id"}
        return self._alert("UNKNOWN_IE", row, evidence, now)

    def _corroborates(self, event: dict) -> str | None:
        """None when a security event can explain a score jump, else why it cannot."""
        if event["verdict"] in PROVEN:
            return None
        if event["verdict"] != V.UNSIGNED_LEGACY or self._requires_signature(event["tag"]):
            return f"verdict {event['verdict']}"
        if not event["submitted"]:
            return "unsigned and never received through the Messages API"
        if event["shadowed"]:
            return "unsigned and flagged SHADOW"
        return None

    async def _anomaly(self, row: MessageRow, now: int) -> Alert | None:
        if row.kind != SCORE_KIND or row.ie_id is None or not isinstance(row.json, dict):
            return None
        score = _score(row.json.get("score"))
        if score is None:
            return None
        before = (row.ms_index, row.wf_index or 0) if row.ms_index is not None else None
        prev = await self.store.previous_score(row.ie_id, self._score_verdicts(), before,
                                               row.block_id)
        if prev is None:
            return None
        delta = score - prev["score"]
        if abs(delta) <= self.cfg.jump_threshold:
            return None
        window = self.cfg.corroboration_window_s
        t = row.ts if row.ts > 0 else now // 1000
        candidates = await self.store.security_events(
            row.ie_id, sorted(self.cfg.security_tags), [*PROVEN, V.UNSIGNED_LEGACY],
            t - window, t)
        ignored = []
        for e in candidates:
            why_not = self._corroborates(e)
            if why_not is None:
                # Suppressed: leave a trace of what explained the jump.
                log.info("ANOMALY not raised for block %s (IE %s, %+.3f): corroborated by "
                         "%s block %s (%s)", to_hex(row.block_id), row.ie_id, delta, e["tag"],
                         to_hex(bytes(e["block_id"])), e["verdict"])
                return None
            ignored.append({"blockId": _hex(e["block_id"]), "tag": e["tag"], "why": why_not})
        evidence = {"score": score, "previousScore": prev["score"], "delta": round(delta, 6),
                    "threshold": self.cfg.jump_threshold,
                    "previousBlockId": _hex(prev["block_id"]), "windowS": window,
                    "ignoredEvents": ignored,
                    "reason": f"score moved by {delta:+.3f} with no trustworthy security event "
                              f"for this IE in the preceding {window} s"}
        return self._alert("ANOMALY", row, evidence, now)

    def _clock_skew(self, row: MessageRow, now: int) -> Alert | None:
        if row.iat is None or row.ts <= 0:
            return None
        skew_ms = row.iat - row.ts * 1000
        if abs(skew_ms) <= self.cfg.clock_skew_s * 1000:
            return None
        direction = "ahead of" if skew_ms > 0 else "behind"
        evidence = {"iatMs": row.iat, "milestoneTsMs": row.ts * 1000,
                    "skewS": abs(skew_ms) / 1000, "limitS": self.cfg.clock_skew_s,
                    "reason": f"signer clock {abs(skew_ms) / 1000:.0f} s {direction} the "
                              f"milestone that confirmed the block"}
        return self._alert("CLOCK_SKEW", row, evidence, now)

    async def _chain(self, row: MessageRow, now: int) -> Alert | None:
        if row.prev is None or row.iss is None or row.seq is None:
            return None
        prev = bytes(row.prev)
        siblings = await self.store.chain_siblings(row.iss, prev, list(PROVEN), row.block_id)
        if siblings:
            evidence = {"iss": row.iss, "seq": row.seq, "prev": to_hex(prev),
                        "siblings": [to_hex(bytes(s["block_id"])) for s in siblings],
                        "reason": "another message of this issuer already continues from "
                                  "the same block"}
            return self._alert("CHAIN_FORK", row, evidence, now)
        head = await self.store.chain_head(row.iss, row.seq, list(PROVEN), row.block_id)
        if head is None or bytes(head["block_id"]) == prev:
            return None  # chain intact, or it starts here as far as this database knows
        known = await self.store.get_message(prev) is not None
        evidence = {"iss": row.iss, "seq": row.seq, "prev": to_hex(prev),
                    "expectedPrev": to_hex(bytes(head["block_id"])), "lastSeenSeq": head["seq"],
                    "prevIndexed": known,
                    "reason": ("prev names an older block of this issuer" if known else
                               "prev names a block this database has never seen")}
        return self._alert("CHAIN_GAP", row, evidence, now)

    # -- R5 DRIFT -----------------------------------------------------------------------------

    async def _drift_rule(self, now: int) -> list[Alert]:
        if self.orion is None:
            return []
        ies = await self._fetch_ies()
        if ies is None:
            # Nothing observed: no alert, but an outage neither starts nor ends a divergence.
            return []
        ledger = {r["ie_id"]: r for r in await self.store.latest_scores(self._score_verdicts())}
        out: list[Alert] = []
        diverging: set[str] = set()
        for ie in ies:
            led = ledger.get(ie.ie_id)
            if led is None:
                continue
            # An unreadable Orion value (missing, null, not a number in range) diverges too:
            # otherwise blanking the attribute would silence the rule.
            delta = None if ie.trust_score is None else ie.trust_score - led["score"]
            if delta is not None and abs(delta) <= self.cfg.drift_epsilon:
                continue
            diverging.add(ie.ie_id)
            ep = self._drift.setdefault(ie.ie_id, _Episode(since_ms=now))
            if ep.alerted or now - ep.since_ms <= self.cfg.drift_grace_s * 1000:
                continue
            ep.alerted = True
            reason = ("Orion's trustScore differs from the score on the ledger" if delta
                      is not None else "Orion value unreadable: trustScore is missing or not "
                                       "a number in [0, 1]")
            evidence = {"entityId": ie.entity_id, "orionTrustScore": ie.trust_score,
                        "orionValue": _orion_value(ie.raw_trust_score),
                        "ledgerScore": led["score"], "ledgerBlockId": _hex(led["block_id"]),
                        "delta": None if delta is None else round(delta, 6),
                        "epsilon": self.cfg.drift_epsilon, "divergingSinceMs": ep.since_ms,
                        "graceS": self.cfg.drift_grace_s, "reason": reason}
            out.append(Alert("DRIFT", SEVERITY["DRIFT"], bytes(led["block_id"]), ie.ie_id,
                             evidence, now, dedupe_key=f"since:{ep.since_ms}"))
        for ie_id in set(self._drift) - diverging:
            del self._drift[ie_id]
        return out

    # -- R8 STALE -----------------------------------------------------------------------------

    async def _stale(self, now: int) -> list[Alert]:
        threshold = int(self.cfg.stale_factor * self.cfg.score_interval_s)
        # Measured on the ledger clock when there is one, so a backfill or a halted
        # coordinator does not make every IE look silent; a halted ledger is reported instead.
        now_s = now // 1000
        latest = await self.store.latest_milestone_ts()
        if latest is None:
            await self._set_status("ledger", "empty")
        elif now_s - latest > threshold:
            await self._set_status("ledger", "stalled",
                                   f"no milestone for {now_s - latest} s; STALE cannot fire")
        else:
            await self._set_status("ledger", "ok")
        ref = now_s if latest is None else min(now_s, latest)
        out: list[Alert] = []
        for r in await self.store.latest_scores(self._score_verdicts()):
            silent = ref - r["ts"]
            if r["ts"] <= 0 or silent <= threshold:
                continue
            evidence = {"lastScoreTsMs": r["ts"] * 1000, "lastBlockId": _hex(r["block_id"]),
                        "silentS": silent, "thresholdS": threshold,
                        "scoreIntervalS": self.cfg.score_interval_s,
                        "reason": f"no trust score on the ledger for {silent} s"}
            out.append(Alert("STALE", SEVERITY["STALE"], bytes(r["block_id"]), r["ie_id"],
                             evidence, now, dedupe_key=f"window:{r['ts']}+{threshold}"))
        return out

    # -- R11 ANCHOR_MISMATCH / ANCHOR_UNVERIFIABLE --------------------------------------------

    async def _anchors(self, now: int) -> list[Alert]:
        if self.anchor is None:
            return []
        batch = self.cfg.anchor_batch
        # Unverified anchors first, then a page of all anchors from a persisted rotating
        # cursor, so every anchor is re-checked however many there are.
        cursor = await self.store.get_rule_state(ANCHOR_CURSOR)
        if not isinstance(cursor, int) or isinstance(cursor, bool):
            cursor = -1
        page = await self.store.anchors_after(cursor, batch)
        await self.store.set_rule_state(
            ANCHOR_CURSOR, page[-1]["seq"] if len(page) == batch else -1, at_ms=now)
        rows: dict[int, dict] = {}
        for r in [*await self.store.anchors_to_verify(batch), *page]:
            rows.setdefault(r["seq"], r)
        out: list[Alert] = []
        unreachable: str | None = None
        waiting = overdue = 0
        for seq in sorted(rows):
            row = rows[seq]
            state, detail, alerts, failure = await self._verify_anchor(row, now, unreachable)
            unreachable = unreachable or failure
            out += alerts
            await self.store.set_anchor_verification(
                seq, state, now, None if detail is None else _clean_text(detail))
            if state != "unverifiable":
                continue
            since = row["verify_since_ms"] if row["verify_state"] == state else None
            since = now if since is None else since
            if now - since <= self.cfg.anchor_unverifiable_grace_s * 1000:
                waiting += 1
                continue
            overdue += 1
            evidence = {"seq": seq, "unverifiableSinceMs": since,
                        "graceS": self.cfg.anchor_unverifiable_grace_s, "detail": detail,
                        "reason": "this anchor could not be checked against IOTA Rebased for "
                                  "longer than the grace period"}
            out.append(Alert("ANCHOR_UNVERIFIABLE", SEVERITY["ANCHOR_UNVERIFIABLE"], None,
                             None, evidence, now, dedupe_key=f"seq:{seq}:since:{since}"))
        if unreachable is not None:
            await self._set_status("anchor", "unreachable", unreachable)
        elif overdue:
            await self._set_status("anchor", "unverifiable", f"{overdue} anchor(s) past grace")
        elif waiting:
            await self._set_status("anchor", "pending", f"{waiting} anchor(s) not verified yet")
        else:
            await self._set_status("anchor", "ok")
        return out

    async def _verify_anchor(self, row: dict, now: int, unreachable: str | None
                             ) -> tuple[str, str | None, list[Alert], str | None]:
        """(verify state, detail, alerts, service failure) for one anchor."""
        seq = row["seq"]
        rec = self._onchain.get(seq)
        if rec is None:
            if unreachable is not None:
                return "unverifiable", f"anchor service unreachable: {unreachable}", [], None
            try:
                rec = await self.anchor.checkpoint(seq)  # type: ignore[union-attr]
            except AnchorUnavailable as exc:
                return "unverifiable", f"anchor service unreachable: {exc}", [], str(exc)
            if rec is None:
                return "unverifiable", "no record on IOTA Rebased (yet)", [], None
            problem = _record_problem(rec, seq)
            if problem is not None:
                return "unverifiable", f"unusable on-chain record: {problem}", [], None
            self._onchain[seq] = rec  # an on-chain record never changes
        alerts = await self._check_anchor(row, rec, now)
        if alerts is None:
            cp = rec["checkpoint"]
            window = f"{cp['from']['index']}..{cp['to']['index']}"
            return "unverifiable", f"milestones {window} not fully indexed", [], None
        if alerts:
            await self.store.set_anchor_status(seq, "mismatch")
            return "mismatch", alerts[0].evidence["reason"], alerts, None
        return "verified", None, [], None

    async def _check_anchor(self, row: dict, rec: dict, now: int) -> list[Alert] | None:
        """Mismatch alerts for one anchor ([] when it holds), None if not checkable yet."""
        seq, cp = row["seq"], rec["checkpoint"]
        frm, to = cp["from"]["index"], cp["to"]["index"]
        digest = checkpoint.hash(cp)
        base = {"seq": seq, "window": {"from": frm, "to": to}, "network": rec.get("network"),
                "tx": rec.get("tx"), "record": rec.get("record"), "checkpointHash": to_hex(digest)}
        out: list[Alert] = []
        mirror = row.get("checkpoint_hash")
        if mirror is not None and bytes(mirror) != digest:
            evidence = {**base, "mirrorCheckpointHash": to_hex(bytes(mirror)),
                        "reason": "the witness.anchor mirror on the private Tangle differs from "
                                  "the checkpoint recorded on IOTA Rebased"}
            out.append(Alert("ANCHOR_MISMATCH", SEVERITY["ANCHOR_MISMATCH"], None, None,
                             evidence, now, dedupe_key=f"seq:{seq}:mirror:{bytes(mirror).hex()}"))
        ids = [bytes(i) for i in await self.store.milestone_ids(frm, to)]
        if len(ids) != to - frm + 1:
            return out or None  # the window is not fully indexed yet
        root = merkle.root(ids)
        if to_hex(root) != cp["msRoot"]:
            evidence = {**base, "onchainMsRoot": cp["msRoot"], "recomputedMsRoot": to_hex(root),
                        "reason": "the milestones indexed for this window do not hash to "
                                  "the root anchored on IOTA Rebased: the private Tangle "
                                  "history differs from what was anchored"}
            out.insert(0, Alert("ANCHOR_MISMATCH", SEVERITY["ANCHOR_MISMATCH"], None, None,
                                evidence, now, dedupe_key=f"seq:{seq}:root:{root.hex()}"))
        return out

    # -- R14 SHADOW ---------------------------------------------------------------------------

    async def _shadow_baseline(self) -> int | None:
        """Confirmation time from which blocks must have come through the Messages API.

        Configured, or the first submission ever received, fixed and persisted once known:
        later deleting submissions (or the stored value) does not move it.
        """
        if self.cfg.shadow_since_ms is not None:
            return self.cfg.shadow_since_ms
        stored = await self.store.get_rule_state(SHADOW_BASELINE)
        if self._shadow_since is None:
            if isinstance(stored, int) and not isinstance(stored, bool):
                self._shadow_since = stored
            else:
                self._shadow_since = await self.store.first_submission_ms()
                if self._shadow_since is None:
                    return None
        if stored != self._shadow_since:
            await self.store.set_rule_state(SHADOW_BASELINE, self._shadow_since)
        return self._shadow_since

    async def _shadow(self, now: int) -> list[Alert]:
        since = await self._shadow_baseline()
        if since is None:
            # Nothing ever came through the Messages API: nothing to tell bypass writes from.
            await self._set_status("shadow", "no-baseline",
                                   "no submission received yet and shadow_since_ms unset")
            return []
        await self._set_status("shadow", "ok")
        until = now - self.cfg.shadow_grace_s * 1000
        if until < since:
            return []
        rows = await self.store.shadow_candidates(
            since, until, sorted(self.cfg.shadow_exempt_tags), self.cfg.batch)
        out: list[Alert] = []
        for r in rows:
            evidence = {"tag": r["tag"], "iss": r["iss"], "verdict": r["verdict"],
                        "msIndex": r["ms_index"], "confirmedAtMs": r["confirmed_ms"],
                        "graceS": self.cfg.shadow_grace_s, "baselineMs": since,
                        "reason": "confirmed on the Tangle but never received through the "
                                  "Messages API: written around the relay"}
            out.append(Alert("SHADOW", SEVERITY["SHADOW"], bytes(r["block_id"]), r["ie_id"],
                             evidence, now))
        return out
