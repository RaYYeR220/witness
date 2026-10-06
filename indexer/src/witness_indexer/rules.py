"""Integrity rules: per-message verdicts and cross-source observations turned into alerts.

Per message (`on_message`, called once the verdict pipeline has stored the row):

- R1 FORGED, R2 UNAUTHORIZED_WRITER, R3 REPLAY, R9 MALFORMED, R10 REVOKED_KEY: the
  pipeline's verdict, with evidence saying why;
- R4 UNSIGNED: an unsigned message on a tag whose writer policy requires signatures;
- R6 UNKNOWN_IE: a message about an Infrastructure Element that Orion does not know;
- R7 ANOMALY: a trust score jump beyond `jump_threshold` with no security event for the IE
  (self-orchestrator error, self-security alert) shortly before it;
- R12 CLOCK_SKEW: the signer's `iat` far from the milestone timestamp;
- R15 CHAIN_GAP: the envelope's `prev` is not the issuer's last seen block;
- R16 CHAIN_FORK: two messages of one issuer continue from the same `prev`.

Periodic (`periodic`):

- R5 DRIFT: Orion's `trustScore` differs from the latest ledger score by more than
  `drift_epsilon` for longer than `drift_grace_s`;
- R8 STALE: no ledger score for an IE within `stale_factor` x `score_interval_s`;
- R11 ANCHOR_MISMATCH: the milestone ids stored for an anchored window no longer hash to the
  `msRoot` recorded on IOTA Rebased (fetched from the anchor service, never taken from the
  private-Tangle mirror), or the `witness.anchor` mirror disagrees with Rebased;
- R14 SHADOW: a confirmed tagged-data block that no submission from the Messages API names,
  `shadow_grace_s` after confirmation (tags in `shadow_exempt_tags` are never relayed).

`rescan` takes the confirmed tagged-data block ids read back from the Tangle (INX or REST) and
reports the ones absent from the database as MISSING_IN_DB. That is what catches a wiped
parallel database, which leaves nothing for the validator to re-verify.

R13 ORPHANED, R17 CONTENT_MISMATCH and R18 DB_TAMPER (and NOT_FOUND) are raised by the
validator, which holds the submissions and the node answers they rest on; they are not
repeated here.

Rules never change a verdict and never conclude from a service they could not ask: with Orion
unreachable there is no DRIFT or UNKNOWN_IE, with the anchor service unreachable no
ANCHOR_MISMATCH, and an unreachable DID resolver only leaves evidence incomplete. The last
observation is reported by `Store.stats()` as `orion`, `anchor` and `resolver`
("ok" | "unreachable").

Alerts are stored (deduplicated by rule, block, IE and dedupe key) and emitted as `alert`
events; the lists returned hold only alerts that were new.
"""

from __future__ import annotations

import json
import logging
import math
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any, ClassVar

from witness_core import checkpoint, envelope, merkle
from witness_core import verdicts as V
from witness_core.bundle import snapshot_keys
from witness_core.envelope import KeyInfo
from witness_core.ids import to_hex
from witness_core.policy import TagRule, WriterPolicy

from . import events
from .anchor_client import AnchorClient, AnchorUnavailable
from .orion import IE, IE_URN, OrionClient, OrionUnavailable
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
}

# Verdicts that prove the issuer: the only messages chain, replay and skew rules look at.
PROVEN = (V.PRODUCER_SIGNED, V.RELAY_ATTESTED)
SCORE_KIND = "trust.score"
# An IE missing from the cached Orion list triggers a refresh, at most this often.
ORION_MISS_REFRESH_S = 5.0


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
    # Blocks confirmed before this are never SHADOW; default: the first submission received.
    shadow_since_ms: int | None = None
    orion_ttl_s: float = 30.0
    anchor_batch: int = 50
    batch: int = 500


@dataclass
class _Episode:
    since_ms: int
    alerted: bool = False


def _hex(b: bytes | None) -> str | None:
    return None if b is None else to_hex(bytes(b))


def _json(data: bytes | None) -> Any:
    def reject(token: str) -> Any:
        raise ValueError(f"non-finite number {token}")

    if data is None:
        return None
    try:
        return json.loads(bytes(data).decode("utf-8"), parse_constant=reject)
    except (ValueError, RecursionError):
        return None


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

    # -- entry points -------------------------------------------------------------------------

    async def on_message(self, row: MessageRow) -> list[Alert]:
        """Rules for one stored message; returns the alerts that were new."""
        now = self._now()
        found: list[Alert | None] = []
        explain = self._EXPLAIN.get(row.verdict or "")
        if explain is not None:
            found.append(await explain(self, row, now))
        if row.verdict == V.UNSIGNED_LEGACY:
            found.append(self._unsigned(row, now))
        if self._content_trusted(row):
            found.append(await self._unknown_ie(row, now))
            found.append(await self._anomaly(row, now))
        if row.verdict in PROVEN:
            found.append(self._clock_skew(row, now))
            found.append(await self._chain(row, now))
        return await self._commit([a for a in found if a is not None])

    async def periodic(self, now_ms: int | None = None) -> list[Alert]:
        """Time-based and cross-source rules (R5, R8, R11, R14); returns new alerts."""
        now = self._now() if now_ms is None else now_ms
        found = await self._drift_rule(now)
        found += await self._stale(now)
        found += await self._anchors(now)
        found += await self._shadow(now)
        return await self._commit(found)

    async def rescan(self, confirmed_block_ids: Iterable[bytes],
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

    async def _commit(self, alerts: list[Alert]) -> list[Alert]:
        new: list[Alert] = []
        for a in alerts:
            async with self.store.transaction():
                if not await self.store.put_alert(a):
                    continue
                if a.rule == "SHADOW" and a.block_id is not None:
                    detail = {"cause": "SHADOW", "graceS": self.cfg.shadow_grace_s}
                    await self.store.set_lifecycle(block_id=a.block_id, sub_id=None,
                                                   status="SHADOW", at_ms=a.ts, detail=detail)
                    await self.store.emit(events.LIFECYCLE, {
                        "blockId": _hex(a.block_id), "subId": None, "status": "SHADOW",
                        "atMs": a.ts, "detail": detail})
                await self.store.emit(events.ALERT, _alert_event(a))
            new.append(a)
        return new

    async def _set_status(self, name: str, status: str, detail: str | None = None) -> None:
        if self._status.get(name) == status:
            return
        await self.store.set_service_status(name, status, detail=detail, at_ms=self._now())
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
        try:
            doc = await self.resolver.adoc(did)
        except ResolverUnavailable as exc:
            await self._set_status("resolver", "unreachable", str(exc))
            return None, f"DID resolver unavailable ({exc})"
        await self._set_status("resolver", "ok")
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
        if row.iss is not None:
            last, nonces = await self.store.issuer_state(row.iss, exclude_block_id=row.block_id)
            if row.seq is not None and last is not None and row.seq <= last:
                reasons.append(f"seq {row.seq} is not above the last accepted seq {last}")
            if row.nonce is not None and row.nonce in nonces:
                reasons.append("nonce already used by this issuer")
        if row.canon_hash is not None:
            for m in await self.store.lookup_canon(row.canon_hash):
                if bytes(m["block_id"]) != row.block_id:
                    reasons.append(f"identical envelope already recorded in block "
                                   f"{to_hex(bytes(m['block_id']))}")
                    break
        evidence = {"iss": row.iss, "seq": row.seq, "nonce": row.nonce,
                    "reasons": reasons or ["flagged as a replay when indexed"]}
        return self._alert("REPLAY", row, evidence, now)

    async def _malformed(self, row: MessageRow, now: int) -> Alert:
        obj = _json(row.data)
        if obj is None:
            reason = "data is not JSON"
        elif envelope.is_envelope(obj):
            check = envelope.verify(obj, row.tag or "", lambda _kid: None)
            reason = (check.reason if check.verdict == V.MALFORMED
                      else f"envelope body does not match the {row.kind} schema")
        else:
            reason = f"body does not match the {row.kind} schema"
        evidence = {"tag": row.tag, "kind": row.kind, "reason": reason}
        return self._alert("MALFORMED", row, evidence, now)

    async def _revoked(self, row: MessageRow, now: int) -> Alert:
        included = row.ts * 1000 if row.ts > 0 else None
        evidence: dict[str, Any] = {"iss": row.iss, "kid": row.kid, "iatMs": row.iat,
                                    "includedAtMs": included, "revokedAtMs": None}
        env = _envelope_of(row)
        if env is not None:
            doc, unavailable = await self._did_doc(env["iss"])
            if unavailable is not None:
                evidence["note"] = f"revocation time unknown: {unavailable}"
            else:
                try:
                    keys = snapshot_keys(doc).get(env["kid"], []) if doc is not None else []
                except ValueError:
                    keys = []
                for k in keys:
                    if k.ed25519_public is not None and _signed_by(env, row.tag or "", k):
                        evidence["revokedAtMs"] = k.revoked_at_ms
                        break
        evidence["reason"] = "signed with a key that was revoked before the block was confirmed"
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
        if any(e["verdict"] in PROVEN or not self._requires_signature(e["tag"])
               for e in candidates):
            return None  # explained by a security event for this IE
        evidence = {"score": score, "previousScore": prev["score"], "delta": round(delta, 6),
                    "threshold": self.cfg.jump_threshold,
                    "previousBlockId": _hex(prev["block_id"]), "windowS": window,
                    "reason": f"score moved by {delta:+.3f} with no security event for this IE "
                              f"in the preceding {window} s"}
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
            # Nothing observed: divergence is timed again from the next observation.
            self._drift.clear()
            return []
        ledger = {r["ie_id"]: r for r in await self.store.latest_scores(self._score_verdicts())}
        out: list[Alert] = []
        diverging: set[str] = set()
        for ie in ies:
            led = ledger.get(ie.ie_id)
            if ie.trust_score is None or led is None:
                continue
            delta = ie.trust_score - led["score"]
            if abs(delta) <= self.cfg.drift_epsilon:
                continue
            diverging.add(ie.ie_id)
            ep = self._drift.setdefault(ie.ie_id, _Episode(since_ms=now))
            if ep.alerted or now - ep.since_ms <= self.cfg.drift_grace_s * 1000:
                continue
            ep.alerted = True
            evidence = {"entityId": ie.entity_id, "orionTrustScore": ie.trust_score,
                        "ledgerScore": led["score"], "ledgerBlockId": _hex(led["block_id"]),
                        "delta": round(delta, 6), "epsilon": self.cfg.drift_epsilon,
                        "divergingSinceMs": ep.since_ms, "graceS": self.cfg.drift_grace_s,
                        "reason": "Orion's trustScore differs from the score on the ledger"}
            out.append(Alert("DRIFT", SEVERITY["DRIFT"], bytes(led["block_id"]), ie.ie_id,
                             evidence, now, dedupe_key=f"since:{ep.since_ms}"))
        for ie_id in set(self._drift) - diverging:
            del self._drift[ie_id]
        return out

    # -- R8 STALE -----------------------------------------------------------------------------

    async def _stale(self, now: int) -> list[Alert]:
        threshold = int(self.cfg.stale_factor * self.cfg.score_interval_s)
        # Measured on the ledger clock when there is one, so a backfill or a halted
        # coordinator does not make every IE look silent.
        ref = now // 1000
        latest = await self.store.latest_milestone_ts()
        if latest is not None:
            ref = min(ref, latest)
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

    # -- R11 ANCHOR_MISMATCH ------------------------------------------------------------------

    async def _anchors(self, now: int) -> list[Alert]:
        if self.anchor is None:
            return []
        out: list[Alert] = []
        reachable = True
        for row in await self.store.anchors(limit=self.cfg.anchor_batch):
            seq = row["seq"]
            if row["status"] == "failed":
                continue
            rec = self._onchain.get(seq)
            if rec is None and reachable:
                try:
                    rec = await self.anchor.checkpoint(seq)
                except AnchorUnavailable as exc:
                    reachable = False
                    await self._set_status("anchor", "unreachable", str(exc))
                    continue
                problem = None if rec is None else _record_problem(rec, seq)
                if problem is not None:
                    reachable = False
                    await self._set_status("anchor", "unreachable", f"checkpoint {seq}: {problem}")
                    continue
                if rec is not None:
                    self._onchain[seq] = rec  # an on-chain record never changes
            if rec is not None:
                out += await self._check_anchor(row, rec, now)
        if reachable:
            await self._set_status("anchor", "ok")
        return out

    async def _check_anchor(self, row: dict, rec: dict, now: int) -> list[Alert]:
        seq, cp = row["seq"], rec["checkpoint"]
        frm, to = cp["from"]["index"], cp["to"]["index"]
        digest = checkpoint.hash(cp)
        base = {"seq": seq, "window": {"from": frm, "to": to}, "network": rec.get("network"),
                "tx": rec.get("tx"), "record": rec.get("record"), "checkpointHash": to_hex(digest)}
        out: list[Alert] = []
        ids = [bytes(i) for i in await self.store.milestone_ids(frm, to)]
        if len(ids) == to - frm + 1:  # otherwise the window is not fully indexed yet
            root = merkle.root(ids)
            if to_hex(root) != cp["msRoot"]:
                evidence = {**base, "onchainMsRoot": cp["msRoot"], "recomputedMsRoot": to_hex(root),
                            "reason": "the milestones indexed for this window do not hash to "
                                      "the root anchored on IOTA Rebased: the private Tangle "
                                      "history differs from what was anchored"}
                out.append(Alert("ANCHOR_MISMATCH", SEVERITY["ANCHOR_MISMATCH"], None, None,
                                 evidence, now, dedupe_key=f"seq:{seq}:root:{root.hex()}"))
        mirror = row.get("checkpoint_hash")
        if mirror is not None and bytes(mirror) != digest:
            evidence = {**base, "mirrorCheckpointHash": to_hex(bytes(mirror)),
                        "reason": "the witness.anchor mirror on the private Tangle differs from "
                                  "the checkpoint recorded on IOTA Rebased"}
            out.append(Alert("ANCHOR_MISMATCH", SEVERITY["ANCHOR_MISMATCH"], None, None,
                             evidence, now, dedupe_key=f"seq:{seq}:mirror:{bytes(mirror).hex()}"))
        if out:
            await self.store.set_anchor_status(seq, "mismatch")
        return out

    # -- R14 SHADOW ---------------------------------------------------------------------------

    async def _shadow(self, now: int) -> list[Alert]:
        since = self.cfg.shadow_since_ms
        if since is None:
            since = await self.store.first_submission_ms()
        if since is None:
            return []  # nothing ever came through the Messages API: no baseline to judge by
        until = now - self.cfg.shadow_grace_s * 1000
        if until < since:
            return []
        rows = await self.store.shadow_candidates(
            since, until, sorted(self.cfg.shadow_exempt_tags), self.cfg.batch)
        out: list[Alert] = []
        for r in rows:
            evidence = {"tag": r["tag"], "iss": r["iss"], "verdict": r["verdict"],
                        "msIndex": r["ms_index"], "confirmedAtMs": r["confirmed_ms"],
                        "graceS": self.cfg.shadow_grace_s,
                        "reason": "confirmed on the Tangle but never received through the "
                                  "Messages API: written around the relay"}
            out.append(Alert("SHADOW", SEVERITY["SHADOW"], bytes(r["block_id"]), r["ie_id"],
                             evidence, now))
        return out
