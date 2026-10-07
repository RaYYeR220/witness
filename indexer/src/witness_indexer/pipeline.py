"""The indexer loop: confirmed milestones in, one atomic database transaction per milestone.

For every milestone the transaction holds the milestone, every block of its white-flag cone,
every tagged-data message with its verdict, blind tokens, trust-score lineage, alerts from
the rules engine, lifecycle completion for messages that were first seen as submissions,
then the cursor, and finally the events. A crash at any point leaves either the whole
milestone or nothing, so a restart simply continues at cursor + 1.

Before the transaction opens, the milestone must continue the stored chain, its cone must
hash to its inclusion Merkle root, and every signing key it needs must have been resolved.
Failures are retried with backoff; their kind and progress are published as service status
(`indexer`, `resolver`, `policy` in `Store.stats()`).
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

import psycopg
from witness_core import codec, merkle, schema
from witness_core.envelope import KeyInfo
from witness_core.policy import TagRule, WriterPolicy

from . import events
from .anchors import AnchorIngest
from .classify import (
    Classifier,
    Decoded,
    KeyResolver,
    ResolverFailed,
    as_key_resolver,
    decode,
    judge,
    message_row,
    resolve_keys,
)
from .didkey import OfflineResolver
from .resolver import DidResolver
from .source import (
    BlockSource,
    ConeBlock,
    ConeMismatch,
    MilestoneData,
    NetworkChanged,
    SourceError,
    SourceUnavailable,
    check_cone,
)
from .store import Alert, MessageRow, Store

log = logging.getLogger(__name__)

NO_PAYLOAD = -1  # blocks.payload_type for a block without a payload or one that does not parse
# Lifecycle states a confirmation by the indexer moves forward; later states are left alone.
BEFORE_CONFIRMED = frozenset({"RECEIVED", "SUBMITTED", "SOLID", "ORPHANED"})
ALLOW_ALL = WriterPolicy(version=0, default=TagRule(["*"], False, True))
# Consecutive failures of one milestone, for reasons that will not go away by themselves,
# before the indexer reports itself stuck there.
STUCK_AFTER = 5
TRANSIENT = (SourceUnavailable, psycopg.OperationalError, TimeoutError, ConnectionError)


class RulesEngine(Protocol):
    def on_message(self, row: MessageRow) -> list[Alert] | Awaitable[list[Alert]]: ...


def _hex(b: bytes | None) -> str | None:
    return None if b is None else "0x" + b.hex()


def _now_ms() -> int:
    return int(time.time() * 1000)


def _reason(e: BaseException) -> str:
    if isinstance(e, ConeMismatch):
        return "cone root mismatch"
    text = str(e) if isinstance(e, SourceError) else f"{type(e).__name__}: {e}"
    return text if len(text) <= 80 else text[:77] + "..."


def _payload_type(raw: bytes) -> tuple[int, codec.TaggedData | None]:
    try:
        payload = codec.parse_block(raw).payload
    except codec.DecodeError:
        return NO_PAYLOAD, None
    if payload is None:
        return NO_PAYLOAD, None
    if isinstance(payload, codec.TaggedData):
        return codec.PAYLOAD_TAGGED_DATA, payload
    if isinstance(payload, codec.MilestonePayload):
        return codec.PAYLOAD_MILESTONE, None
    return payload.type, None


class Indexer:
    def __init__(self, source: BlockSource, store: Store,
                 classify: Classifier = schema.classify,
                 rules: RulesEngine | None = None,
                 policy: WriterPolicy | None = None,
                 resolve: KeyResolver | Callable[[str], KeyInfo | None] | None = None, *,
                 policy_mode: str | None = None,
                 anchor_did: str | None = None,
                 sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
                 now_ms: Callable[[], int] = _now_ms,
                 initial_backoff_s: float = 0.5, max_backoff_s: float = 8.0) -> None:
        self.source = source
        self.store = store
        self.classify = classify
        self.rules = rules
        # Without a policy no signer is listed, so every signed message is UNAUTHORIZED_WRITER.
        self.policy = policy if policy is not None else WriterPolicy(version=0)
        self.policy_mode = policy_mode or (
            "none" if policy is None else "allow-any" if policy == ALLOW_ALL else "file")
        self.resolver = as_key_resolver(resolve if resolve is not None else OfflineResolver())
        # witness.anchor mirrors of this DID become rows of `anchors`; None: never.
        self.anchors = AnchorIngest(anchor_did)
        self._sleep = sleep
        self._now_ms = now_ms
        self._initial = initial_backoff_s
        self._max = max_backoff_s
        self._stopping = False
        self._task: asyncio.Task | None = None
        self._idle = asyncio.Event()  # cleared while a milestone transaction is open
        self._idle.set()
        self.last_index = 0
        self._published: dict[str, tuple[str, str | None]] = {}
        self._failing: tuple[int, int] = (0, 0)  # (milestone, consecutive failures)
        # (milestone, kid, consecutive failures) of the key resolver
        self._resolver_failing: tuple[int, str, int] = (0, "", 0)

    # -- loop -------------------------------------------------------------------------------

    async def sync(self) -> int:
        """Index from cursor + 1 until the source ends; returns the last indexed milestone.
        Source and database errors propagate."""
        start = await self.store.get_cursor() + 1
        self.last_index = start - 1
        await self._publish("policy", self.policy_mode)
        if isinstance(self.resolver, DidResolver) and self.resolver.base_url is None:
            # A configuration choice, not an outage: only did:key (and pinned) DIDs resolve,
            # every other signer is FORGED ("signing key not resolvable").
            await self._publish("resolver", "disabled")
        elif self.resolver is not None:
            # Replace whatever an earlier process left in the status table: until a lookup
            # fails in this process, the resolver counts as reachable.
            await self._publish("resolver", "ok")
        log.info("indexing from milestone %d via %s", start, self.source.name)
        async for m in self.source.milestones(start):
            if m.index <= self.last_index:
                continue  # resent after a reconnect
            if m.index != self.last_index + 1:
                log.warning("milestones %d..%d are not available from %s; continuing at %d",
                            self.last_index + 1, m.index - 1, self.source.name, m.index)
            self._idle.clear()  # stop() waits for the milestone and its status to land
            try:
                await self.process_milestone(m)
                self.last_index = m.index
                self._failing = (0, 0)
                self._resolver_failing = (0, "", 0)
                await self._publish("indexer", "ok")
                if self._published.get("resolver", ("",))[0] == "unreachable":
                    await self._publish("resolver", "ok")
            finally:
                self._idle.set()
            if self._stopping:
                break
        return self.last_index

    async def run(self) -> None:
        """Index forever: reconnect with exponential backoff whenever the source or the
        database fails, until `stop()`."""
        self._task = asyncio.current_task()
        backoff = self._initial
        try:
            while not self._stopping:
                before = self.last_index
                try:
                    await self.sync()
                    log.info("%s stream ended at milestone %d; reconnecting",
                             self.source.name, self.last_index)
                except asyncio.CancelledError:
                    raise
                except Exception as e:  # noqa: BLE001 - keep indexing through outages
                    await self._failed(e)
                if self._stopping:
                    break
                if self.last_index > before:
                    backoff = self._initial
                await self._sleep(backoff)
                backoff = min(backoff * 2, self._max)
        except asyncio.CancelledError:
            if not self._stopping:
                raise

    async def stop(self, grace_s: float = 10.0) -> None:
        """Stop `run()`. A milestone being written is allowed `grace_s` to commit; the loop
        is cancelled only while it waits for the node (or when the grace period runs out)."""
        self._stopping = True
        task = self._task
        if task is None or task is asyncio.current_task() or task.done():
            return
        try:
            await asyncio.wait_for(asyncio.shield(self._idle.wait()), grace_s)
        except TimeoutError:
            log.warning("milestone %d still being written after %g s; abandoning it",
                        self.last_index + 1, grace_s)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    # -- health -----------------------------------------------------------------------------

    async def _publish(self, name: str, status: str, detail: str | None = None) -> None:
        """Record a service status in the store, when it changed. Never raises: the database
        may be the thing that is down."""
        if self._published.get(name) == (status, detail):
            return
        try:
            await self.store.set_service_status(name, status, detail=detail)
        except Exception as e:  # noqa: BLE001
            log.debug("could not record %s status %r: %s", name, status, e)
            return
        self._published[name] = (status, detail)

    async def _failed(self, e: Exception) -> None:
        """Log and publish why indexing stopped; `run` then backs off and retries."""
        index = self.last_index + 1
        detail = f"{type(e).__name__}: {e}"[:500]
        if isinstance(e, NetworkChanged):
            log.error("refusing milestone %d: %s", index, e)
            await self._publish("indexer", "network changed", str(e)[:500])
        elif isinstance(e, ResolverFailed):
            prev, prev_kid, count = self._resolver_failing
            count = count + 1 if (prev, prev_kid) == (index, e.kid) else 1
            self._resolver_failing = (index, e.kid, count)
            await self._publish("resolver", "unreachable", detail)
            if count >= STUCK_AFTER:
                if count == STUCK_AFTER:
                    log.error("stuck at milestone %d: key %s unresolvable after %d attempts: %s",
                              index, e.kid[:120], count, e)
                await self._publish("indexer", f"stuck at {index} (resolver: {e.kid[:64]})",
                                    detail)
            else:
                log.warning("key resolver unreachable at milestone %d (attempt %d), "
                            "retrying: %s", index, count, e)
                await self._publish("indexer", "retrying (resolver unreachable)", detail)
        elif isinstance(e, TRANSIENT):
            what = "database" if isinstance(e, psycopg.OperationalError) else self.source.name
            log.warning("%s unavailable after milestone %d, retrying: %s", what,
                        self.last_index, detail)
            await self._publish("indexer", f"retrying ({what} unavailable)", detail)
        else:  # the same input will fail the same way: count it
            prev, count = self._failing
            count = count + 1 if prev == index else 1
            self._failing = (index, count)
            reason = _reason(e)
            if count >= STUCK_AFTER:
                if count == STUCK_AFTER:
                    log.error("stuck at milestone %d after %d attempts: %s", index, count,
                              detail, exc_info=e)
                await self._publish("indexer", f"stuck at {index} ({reason})", detail)
            else:
                log.warning("milestone %d failed (attempt %d): %s", index, count, detail)
                await self._publish("indexer",
                                    f"retrying milestone {index} ({reason}, attempt {count})",
                                    detail)

    # -- one milestone ----------------------------------------------------------------------

    async def _check_continuity(self, m: MilestoneData) -> None:
        """Refuse milestones of another network than the one already stored."""
        same = await self.store.milestone(m.index)
        if same is not None and bytes(same["id"]) != m.id:
            raise NetworkChanged(f"milestone {m.index} is {_hex(m.id)} on the node but "
                                 f"{_hex(bytes(same['id']))} in the database")
        before = await self.store.milestone(m.index - 1) if m.index > 1 else None
        if before is not None and bytes(before["id"]) != m.prev_id:
            raise NetworkChanged(f"milestone {m.index} follows {_hex(m.prev_id)} but milestone "
                                 f"{m.index - 1} in the database is {_hex(bytes(before['id']))}")

    async def process_milestone(self, m: MilestoneData) -> None:
        await self._check_continuity(m)
        cone = check_cone(m.index, [b async for b in self.source.cone(m.index)])
        root = merkle.root([b.block_id for b in cone])
        if root != m.inclusion_root:
            raise ConeMismatch(f"milestone {m.index}: cone of {len(cone)} blocks hashes to "
                               f"{_hex(root)}, the milestone commits to {_hex(m.inclusion_root)}")
        parsed = [(b, *_payload_type(b.raw)) for b in cone]
        decoded = {b.block_id: decode(payload.tag, payload.data, self.classify)
                   for b, _, payload in parsed if payload is not None}
        keys = await resolve_keys(self.resolver, decoded.values(), m.timestamp * 1000)

        pending: list[tuple[str, dict]] = []
        async with self.store.transaction():
            cursor = await self.store.get_cursor()
            new_ms = await self.store.put_milestone(
                m.index, m.id, m.timestamp, m.essence, m.signature_dicts(), m.inclusion_root,
                m.prev_id)
            tagged: list[tuple[ConeBlock, codec.TaggedData]] = []
            for b, ptype, payload in parsed:
                await self.store.put_block(b.block_id, m.index, b.wf_index, b.raw, ptype)
                if payload is not None:
                    tagged.append((b, payload))
            new_messages = 0
            for b, payload in tagged:
                if await self._message(m, b, payload, decoded[b.block_id], keys, pending):
                    new_messages += 1
            if m.index > cursor:
                await self.store.set_cursor(m.index)
            if new_ms:
                pending.insert(0, (events.MILESTONE, {
                    "index": m.index, "id": _hex(m.id), "ts": m.timestamp,
                    "blocks": len(cone), "messages": len(tagged), "newMessages": new_messages,
                }))
            for etype, payload in pending:
                await self.store.emit(etype, payload)

    async def _message(self, m: MilestoneData, b: ConeBlock, payload: codec.TaggedData,
                       d: Decoded, keys: dict[str, KeyInfo | None],
                       pending: list[tuple[str, dict]]) -> bool:
        j = await judge(self.store, self.policy, keys, d, b.block_id, m.timestamp)
        row = message_row(d, j, block_id=b.block_id, data=payload.data, ms_index=m.index,
                          wf_index=b.wf_index, ts=m.timestamp)
        result = await self.store.put_message(row)
        if result is None:
            return False  # already indexed with its milestone position
        for token in d.blind_tokens:
            await self.store.put_blind(token, b.block_id)
        if d.score is not None and row.ie_id is not None:
            await self.store.put_ie_score(row.ie_id, m.index, m.timestamp, d.score, b.block_id,
                                          row.verdict)
        pending.append((events.MESSAGE, {
            "blockId": _hex(b.block_id), "tag": row.tag, "kind": row.kind,
            "verdict": row.verdict, "ieId": row.ie_id, "iss": row.iss, "seq": row.seq,
            "msIndex": m.index, "wfIndex": b.wf_index, "ts": m.timestamp,
            "encrypted": row.encrypted, "reason": j.reason, "first": result == "inserted",
        }))
        await self._confirm_lifecycle(m, b.block_id, pending)
        await self.anchors.on_message(self.store, row, d, self._now_ms(), pending)
        if self.rules is not None:
            alerts = self.rules.on_message(row)
            if inspect.isawaitable(alerts):
                alerts = await alerts
            for a in alerts or ():
                if await self.store.put_alert(a):
                    pending.append((events.ALERT, {
                        "rule": a.rule, "severity": a.severity, "blockId": _hex(a.block_id),
                        "ieId": a.ie_id, "ts": a.ts, "evidence": a.evidence,
                    }))
        return True

    async def _confirm_lifecycle(self, m: MilestoneData, block_id: bytes,
                                 pending: list[tuple[str, dict]]) -> None:
        """A message that came in as a submission is confirmed now that a milestone
        references it, unless its validation already went further."""
        history = await self.store.lifecycle(block_id)
        if not history or history[-1]["status"] not in BEFORE_CONFIRMED:
            return
        latest = history[-1]
        at = self._now_ms()
        detail = {"source": "indexer", "via": self.source.name, "msIndex": m.index,
                  "msTimestamp": m.timestamp}
        if latest["status"] == "ORPHANED":
            detail["after"] = "ORPHANED"
        await self.store.set_lifecycle(block_id=block_id, sub_id=latest["sub_id"],
                                       status="CONFIRMED", at_ms=at, detail=detail)
        pending.append((events.LIFECYCLE, {
            "blockId": _hex(block_id), "subId": latest["sub_id"], "status": "CONFIRMED",
            "atMs": at, "detail": detail,
        }))
