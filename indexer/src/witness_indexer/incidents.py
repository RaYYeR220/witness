"""Incident Explorer: correlated trust events on one timeline, each verifiable by its block id.

aeriOS writes the pieces of a security story to the Tangle from different components: the
Trust Manager lowers an IE's `trust.score` after Suricata alerts, the self-orchestrator
reports an `errorCode` for the IE, an LLO reports "Service component failed" for a component
running on it. The engine groups them into incidents.

Triggers (a message or alert that may open an incident):

- a `trust.score` that drops by at least `drop_threshold` below the IE's previous score (the
  previous proven one for a proven score, the previous proven or relayed one for a relayed
  score);
- a `self-orchestrator` message with a non-zero, non-empty `errorCode`;
- an LLO (`LLO-K8s` / `LLO-Docker`) "Service component failed";
- a message on one of `security_tags` naming an IE (e.g. `self-security`);
- a critical or high alert on a proven or relayed block (CHAIN_FORK, ...);
- a witnessed attack (`ATTACK_RULES`: FORGED, REPLAY, UNAUTHORIZED_WRITER, REVOKED_KEY at
  critical/high) on a message that names an IE Orion knows, directly or through a service
  component Orion places on it: a forgery attempt shows up as an incident on the IE it
  targets. Naming an IE costs an attacker nothing, so an IE Orion does not list (or any IE
  while Orion has never answered) leaves the alert alert-only: it may join an incident
  already open on that IE, never open one;
- an alert about the explorer's own records (`INTEGRITY_RULES`: DB_TAMPER, MISSING_IN_DB,
  ANCHOR_MISMATCH, ...), grouped into a `ledger` incident unless it names an IE.

Correlation: an incident has keys (`ie:<IE id>`, `sc:<service component>`, `iss:<issuer>`,
`ledger`). An event joins the open incident it shares a key with when it happened within
`window_ms` of that incident's latest event; otherwise a trigger opens a new incident. An LLO
report joins the incident of the IE its component runs on: the component -> IE relationship
comes from Orion's ServiceComponent entities, else the component id alone is the key. Orion's
IE list and that relationship are fetched only outside a database transaction (2 s and
`orion_max_bytes` budget, cached `orion_ttl_s`; a failed refresh keeps the last answer and is
reported as `incident-orion`). The LLO's k8s resource name
(`urn-ngsi-ld-service-<id>-component-<name>`) and the Orion entity id are lined up.

Trust: every block is judged at one of three levels.

- proven: PRODUCER_SIGNED by a writer the policy allows for the tag, with no UNSIGNED or
  SHADOW alert on the block. Only proven events shape an incident: set its baseline and low
  score, add correlation keys or its IE, act as `remediation`, close it on recovery, and
  move its anchor (below).
- relayed: RELAY_ATTESTED by an allowed writer, or UNSIGNED_LEGACY with a submission from
  the Messages API on a tag that does not require signatures, and no UNSIGNED or SHADOW
  alert. Submission records come from an unauthenticated broker and the relay accepts anyone
  inside the cluster, so a relayed event may only open an incident or join one as a trigger
  (stock aeriOS components write unsigned through the relay, and a false alarm beats a
  missed one). It never shapes, remediates or closes one, and moves its latest event at
  most one window past the anchor (its opening or latest proven event), so relayed traffic
  cannot keep an incident open.
- untrusted: anything else (FORGED, REPLAY, written around the relay, R4 UNSIGNED, a
  verdict the engine does not know, ...). Its content is never evidence. It counts only
  through the attack alert Witness raised about it (above): that alert opens an incident on
  an IE Orion knows, or joins one already open on the IE it names, raising its severity,
  but never touches its anchor, keys, IE, recovery target or status.
- Alerts about the explorer's own records count the same way: they open or join and shape
  nothing. Attack and integrity alerts can be provoked by anyone who can write a block or a
  submission record, so like relayed events they move an incident's latest event at most
  one window past its anchor, and an alert on a block already in an incident moves it only
  as far as that block's own trust level allows (none for evidence-only blocks).

The policy check is the engine's own (the writer policy the indexer was started with is a
required argument), not only the rules' UNSIGNED alert, so a rules failure cannot promote an
unsigned write.
A SHADOW alert found after the fact (R14 runs 30 s after confirmation) takes back what the
block did: its event becomes `alert` evidence, an incident it closed reopens, and the
recovery target is recomputed from the proven drops that remain.

Every event carries its block id and a role: `trigger` (the event that opened the incident),
`trust-drop`, `security`, `deployment` (LLO reports), `remediation` (a cleared self-
orchestrator code, the recovered trust score) or `alert`. An incident's severity is the
highest of its members'.

Time: an event's time is its confirming milestone's time, or the relay's receipt time when
that lies within one window before it (a submission record states its own receipt time and
the broker is unauthenticated, so a record from the future cannot stretch an incident).

Close: `closed:recovered` when, after a trust drop, a PROVEN trust.score is back to (or above)
the level the incident's first drop fell from; `closed:quiet` after `quiet_close_ms` with no
new event (measured on the ledger clock, so a backfill does not close incidents early). An
incident without a trust drop (an orchestrator error alone) closes quietly.

Delivery: each change (opened / attached / updated / closed) is emitted as an `incident` event
in the same transaction. A configured `AlertPublisher` sends committed ones, as compact JSON,
to MQTT `witness/alerts/{severity}` (QoS 1): `flush()` reads the events log from a persisted
cursor, so nothing is published for a transaction that rolls back and a broker outage only
delays alerts. Only the publisher task (`run_publisher`) talks to the broker; message and
periodic processing just wake it. Publishing never breaks indexing (`alerts-mqtt: ok |
unreachable` in `Store.stats()`).

Robustness, as in rules.py: text from messages is sanitised before it is stored or published,
every step runs in a savepoint, a failure is logged and reported (`incident-engine: error`;
`incidents` itself is the table count in `Store.stats()`) and never raised into the caller's
transaction, and no HTTP happens inside a transaction.

`CorrelatedRules(rules, incidents)` is what the indexer (`main.py`) runs in place of the
rules engine: it returns the rules' alerts and runs the incident engine after them, per
message (inside the milestone transaction) and per periodic pass (which also picks up the
alerts the validator and the periodic rules raise); `run_publisher` is its own service.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import logging
import math
import re
import time
import unicodedata
from collections.abc import Callable
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import unquote, urlsplit

from witness_core import policy as writer_policy
from witness_core import verdicts as V
from witness_core.ids import from_hex, to_hex
from witness_core.policy import WriterPolicy

from . import events
from .orion import OrionClient, ie_id_of
from .rules import _clean as _clean_value
from .rules import _clean_text
from .store import Alert, MessageRow, Store

__all__ = ["AlertPublisher", "CorrelatedRules", "IncidentConfig", "IncidentEngine",
           "MqttAlertPublisher", "component_key"]

log = logging.getLogger(__name__)

SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
TRIGGER_SEVERITIES = ["critical", "high"]
# Alerts about the explorer's own records rather than about what a writer claimed.
INTEGRITY_RULES = frozenset({"MISSING_IN_DB", "DB_TAMPER", "ANCHOR_MISMATCH",
                             "CONTENT_MISMATCH", "NOT_FOUND", "ORPHANED"})
# Alerts that a writer attacked the record of whatever IE its message names.
ATTACK_RULES = frozenset({"FORGED", "REPLAY", "UNAUTHORIZED_WRITER", "REVOKED_KEY"})
RULE_TITLES = {
    "FORGED": "Forged message",
    "REPLAY": "Replayed message",
    "UNAUTHORIZED_WRITER": "Write by an unauthorized issuer",
    "REVOKED_KEY": "Message signed with a revoked key",
    "SHADOW": "Write around the Messages API",
    "CHAIN_FORK": "Issuer chain fork",
    "MISSING_IN_DB": "Confirmed block missing from the database",
    "DB_TAMPER": "Stored record altered",
    "ANCHOR_MISMATCH": "Ledger history differs from its IOTA Rebased anchor",
    "CONTENT_MISMATCH": "Tangle content differs from the submitted message",
    "NOT_FOUND": "Submitted block not found on the Tangle",
    "ORPHANED": "Submitted block never confirmed",
}
SCORE_KIND = "trust.score"
ORCHESTRATOR_KIND = "self-orchestrator"
LLO_KINDS = frozenset({"llo.k8s", "llo.docker"})
LLO_FAILED = "service component failed"
LEDGER = "ledger"
OPEN = "open"
CLOSED_RECOVERED = "closed:recovered"
CLOSED_QUIET = "closed:quiet"
ENGINE_STATUS = "incident-engine"
ORION_STATUS = "incident-orion"
MQTT_STATUS = "alerts-mqtt"
# Last `alert` event of the events log the periodic pass has correlated. Event ids follow
# commit order (Store.emit serialises emitters), alert ids do not: a cursor over alert ids
# would skip an alert whose transaction commits after a later one.
ALERT_CURSOR = "incidents.alert_event_cursor"
PUBLISH_CURSOR = "incidents.mqtt_cursor"
PROVEN = "proven"
RELAYED = "relayed"
UNTRUSTED = "untrusted"
WITNESSED = "witnessed"  # how an attack or integrity alert moves an incident
# Alerts that take a block's content out of evidence whatever its verdict.
DISTRUST_RULES = frozenset({"SHADOW", "UNSIGNED"})
TITLE_MAX = 160
ID_MAX = 120
EPS = 1e-9
_K8S_COMPONENT = re.compile(r"(?i)urn-ngsi-ld-service-([a-f0-9]+)-component-([a-z0-9-]+)")


@dataclass(frozen=True)
class IncidentConfig:
    window_ms: int = 600_000
    quiet_close_ms: int = 1_800_000
    drop_threshold: float = 0.2
    mqtt_topic_prefix: str = "witness/alerts"
    security_tags: frozenset[str] = frozenset({"self-security"})
    orion_ttl_s: float = 60.0
    orion_timeout_s: float = 2.0
    orion_max_bytes: int = 2 * 1024 * 1024  # per listing; larger skips the refresh
    orion_max_entries: int = 50_000
    alert_batch: int = 500
    publish_batch: int = 200
    publish_timeout_s: float = 5.0
    publish_poll_s: float = 2.0
    # `incident-engine: error` stays up this long after the last failure.
    error_hold_s: int = 600


class AlertPublisher(Protocol):
    async def publish(self, topic: str, payload: bytes) -> None:
        """Deliver one message (QoS 1); raise if it could not be delivered."""


# -- text and values --------------------------------------------------------------------------

def _label(v: Any, limit: int = TITLE_MAX) -> str:
    """One printable line: control, format and surrogate characters escaped, whitespace
    collapsed, cut to `limit`."""
    s = v if isinstance(v, str) else repr(v)
    s = s[:limit * 4]
    out = []
    for ch in s:
        if ch in "\t\n\r":
            out.append(" ")
        elif unicodedata.category(ch)[0] == "C":
            out.append(f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    s = " ".join("".join(out).split())
    return s if len(s) <= limit else s[:limit - 1] + "…"


def _ident(v: str) -> str:
    return _label(v, ID_MAX)


def component_key(service_component_id: str) -> str:
    """The id an LLO reports (its k8s resource name, `urn-ngsi-ld-service-<id>-component-
    <name>`) and the Orion entity id (`urn:ngsi-ld:Service:<id>:Component:<name>`) give the
    same key; any other id is its own key. Case-insensitive, like the LLO's own mapping."""
    s = service_component_id.strip()
    m = _K8S_COMPONENT.fullmatch(s)
    if m:
        s = f"urn:ngsi-ld:Service:{m[1]}:Component:{m[2]}"
    return s.lower()


def _hex(b: bytes | memoryview | None) -> str | None:
    return None if b is None else to_hex(bytes(b))


def _score(v: Any) -> float | None:
    if isinstance(v, bool) or not isinstance(v, int | float):
        return None
    v = float(v)
    return v if math.isfinite(v) and 0 <= v <= 1 else None


def _is_error(code: Any) -> bool:
    if isinstance(code, bool):
        return code
    if isinstance(code, int):
        return code != 0
    if isinstance(code, float):
        return math.isfinite(code) and code != 0
    if isinstance(code, str):
        return code.strip() not in ("", "0")
    return False


def _msg_time(m: dict | MessageRow | None, window_ms: int) -> int | None:
    """When a message happened, on the ledger clock: its milestone's time (else its
    confirmation time), or the relay's receipt time when that lies within `window_ms` before
    it. A submission record states its own receipt time, so one outside that range (a
    clock far ahead, a record from the future) is not believed. None while unconfirmed."""
    if m is None:
        return None
    get = m.get if isinstance(m, dict) else (lambda k: getattr(m, k, None))
    ts, confirmed, received = get("ts"), get("confirmed_at_ms"), get("received_at_ms")
    if _int(ts) and ts > 0:
        ledger = ts * 1000
    elif _int(confirmed) and confirmed > 0:
        ledger = confirmed
    else:
        return None
    if _int(received) and ledger - window_ms <= received <= ledger:
        return received
    return ledger


def _max_sev(a: str | None, b: str | None) -> str | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if SEV_RANK.get(a, -1) >= SEV_RANK.get(b, -1) else b


def _int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


# -- observations -----------------------------------------------------------------------------

@dataclass
class _Obs:
    """One event as the engine sees it."""
    block_id: bytes | None
    keys: set[str]
    at_ms: int
    role: str                     # its role when it joins an open incident
    level: str                    # PROVEN, RELAYED or UNTRUSTED
    opens: bool = False           # a trigger
    witnessed: bool = False       # an attack or integrity alert: Witness's own observation
    severity: str | None = None
    title: str = ""
    ie_id: str | None = None
    detail: dict = field(default_factory=dict)
    score: float | None = None
    baseline: tuple[float, bytes] | None = None
    position: tuple[int, int] | None = None
    alert: dict | None = None

    @property
    def proven(self) -> bool:
        return self.level == PROVEN


@dataclass
class _Step:
    changes: list[dict] = field(default_factory=list)
    attached: set[bytes] = field(default_factory=set)


def _change(action: str, inc: dict, *, block_id: bytes | None = None, role: str | None = None,
            at_ms: int | None = None, rule: str | None = None) -> dict:
    out = {"action": action, "incidentId": inc["id"], "status": inc["status"],
           "severity": inc["severity"], "title": inc["title"], "ieId": inc["ie_id"],
           "blockId": _hex(block_id), "role": role, "atMs": at_ms, "rule": rule}
    return {k: v for k, v in out.items() if v is not None}


class IncidentEngine:
    def __init__(self, store: Store, orion: OrionClient | None = None,
                 cfg: IncidentConfig | None = None, publisher: AlertPublisher | None = None, *,
                 policy: WriterPolicy, now_ms: Callable[[], int] | None = None) -> None:
        """`policy` is the writer policy the indexer judges with (required: a block's trust
        level is never decided without it)."""
        if not isinstance(policy, WriterPolicy):
            raise TypeError("IncidentEngine needs the indexer's WriterPolicy")
        self.store = store
        self.orion = orion
        self.policy = policy
        self.cfg = cfg or IncidentConfig()
        self.publisher = publisher
        self._now = now_ms or (lambda: int(time.time() * 1000))
        self._hosts: dict[str, str] = {}  # component_key -> IE id
        self._known_ies: frozenset[str] | None = None  # None: Orion never answered
        self._orion_at = -math.inf
        self._cursor: int | None = None  # last incident event handed to the publisher
        self._saved_cursor: int | None = None
        self._flush_lock = asyncio.Lock()
        self._wake: asyncio.Event | None = None
        self._stopping = False
        self._status: dict[str, str] = {}
        self._last_error_ms: int | None = None

    # -- entry points ---------------------------------------------------------------------------

    async def on_message(self, row: MessageRow) -> list[dict]:
        """Correlate one stored message (and the alerts already raised on its block); returns
        the incident changes it caused. Never raises; inside the caller's transaction only
        its own statements roll back on failure."""
        changes: list[dict] = []
        try:
            if not self.store.in_transaction():
                await self._refresh_orion()
            async with self.store.transaction(), self.store.savepoint():
                await self._init_cursor()
                changes = await self._message(row)
        except Exception as exc:  # noqa: BLE001 - the indexer goes on whatever a message does
            changes = []
            await self._failed("message", exc)
        self._notify()
        return changes

    async def periodic(self, *, now_ms: int) -> list[dict]:
        """Alerts raised since the last pass (validator, periodic rules) and quiet closes.
        Returns the incident changes. Like on_message, it never talks to the broker itself:
        it wakes the publisher task (`run_publisher`)."""
        changes: list[dict] = []
        if not self.store.in_transaction():
            await self._refresh_orion()
        try:
            async with self.store.savepoint():
                await self._init_cursor()
        except Exception as exc:  # noqa: BLE001 - logged and reported by _failed
            await self._failed("cursor", exc)
        for name, fn in (("alerts", self._scan_alerts), ("quiet", self._quiet)):
            try:
                async with self.store.transaction(), self.store.savepoint():
                    await self.store.emit_lock()
                    step = _Step()
                    await fn(step, now_ms)
                    await self._emit(step)
                changes += step.changes
            except Exception as exc:  # noqa: BLE001 - one step must not stop the other
                await self._failed(name, exc)
        self._notify()
        last = self._last_error_ms
        if last is None or self._now() - last > self.cfg.error_hold_s * 1000:
            with contextlib.suppress(Exception):
                await self._set_status(ENGINE_STATUS, "ok")
        return changes

    async def timeline(self, incident_id: int, *, limit: int = 500) -> dict | None:
        """The incident and its first `limit` events in time order (and alerts). Each event
        names its block, the message's verdict and its lifecycle status, and the proof to
        check it against (`/proofs/{blockId}`). `eventsTotal` / `alertsTotal` say how many
        there are in all; Store.incident_timeline pages through the rest."""
        inc = await self.store.incident_header(incident_id)
        if inc is None:
            return None
        rows = await self.store.incident_timeline(incident_id, limit=limit)
        alerts = await self.store.incident_alerts(incident_id, limit=limit)
        counts = await self.store.incident_counts(incident_id)
        return {
            "incident": {
                "id": inc["id"], "title": inc["title"], "severity": inc["severity"],
                "status": inc["status"], "ieId": inc["ie_id"], "keys": list(inc["keys"]),
                "openedAtMs": inc["opened_at_ms"], "closedAtMs": inc["closed_at_ms"],
                "lastEventMs": inc["last_event_ms"], "baselineScore": inc["baseline_score"],
                "lowScore": inc["low_score"], "closedBy": _hex(inc["closed_by"]),
            },
            "events": [self._event_view(r) for r in rows],
            "eventsTotal": counts["events"], "alertsTotal": counts["alerts"],
            "alerts": [{"id": a["id"], "rule": a["rule"], "severity": a["severity"],
                        "blockId": _hex(a["block_id"]), "ieId": a["ie_id"], "ts": a["ts"],
                        "reason": (a["evidence"] or {}).get("reason")} for a in alerts],
        }

    async def flush(self) -> int:
        """Publish committed incident events not sent yet; returns how many went out. Does
        nothing inside a transaction (its events are not committed) or without a publisher.
        Never raises."""
        if self.publisher is None or self.store.in_transaction():
            return 0
        async with self._flush_lock:
            try:
                return await self._flush()
            except Exception as exc:  # the database, not the broker: retried next time
                log.exception("publishing incident alerts failed")
                with contextlib.suppress(Exception):
                    await self._set_status(MQTT_STATUS, "error", f"{type(exc).__name__}: {exc}")
                return 0

    async def run_publisher(self) -> None:
        """Deliver alerts as their transactions commit (polls every `publish_poll_s`); a last
        delivery attempt when stopped."""
        self._stopping = False
        self._wake = asyncio.Event()
        while not self._stopping:
            await self.flush()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), self.cfg.publish_poll_s)
            self._wake.clear()
        await self.flush()

    def _notify(self) -> None:
        """Wake the publisher: there may be committed changes to deliver."""
        if self._wake is not None:
            self._wake.set()

    async def stop_publisher(self) -> None:
        self._stopping = True
        if self._wake is not None:
            self._wake.set()

    async def aclose(self) -> None:
        close = getattr(self.publisher, "aclose", None)
        if close is not None:
            with contextlib.suppress(Exception):
                await close()

    # -- one message ----------------------------------------------------------------------------

    async def _message(self, row: MessageRow) -> list[dict]:
        obs = await self._observe(row)
        alerts = sorted((a for a in await self.store.alerts({"block_id": row.block_id})
                         if a["severity"] in TRIGGER_SEVERITIES), key=lambda a: a["id"])
        if obs is None and not alerts:
            return []
        if (obs is not None and not obs.opens and not alerts
                and not await self.store.open_incidents(sorted(obs.keys))):
            return []  # context with nothing open to join: the common case, no lock taken
        await self.store.emit_lock()
        step = _Step()
        if obs is not None:
            await self._correlate(obs, step)
        for a in alerts:
            await self._alert(a, step)
        await self._emit(step)
        return step.changes

    async def _trust(self, block_id: bytes, verdict: str | None, tag: str | None,
                     iss: str | None) -> str:
        """PROVEN, RELAYED or UNTRUSTED (see the module docstring); anything unexpected is
        UNTRUSTED."""
        if verdict not in (V.PRODUCER_SIGNED, V.RELAY_ATTESTED, V.UNSIGNED_LEGACY):
            return UNTRUSTED
        if verdict == V.UNSIGNED_LEGACY:
            rule = self.policy.tags.get(tag or "", self.policy.default)
            if rule.require_signature and not rule.legacy_grace:
                return UNTRUSTED
        elif not (isinstance(iss, str) and isinstance(tag, str)
                  and writer_policy.allowed(self.policy, tag, iss)):
            return UNTRUSTED
        if await self.store.block_alert_rules(block_id) & DISTRUST_RULES:
            return UNTRUSTED
        if verdict == V.PRODUCER_SIGNED:
            return PROVEN
        if verdict == V.RELAY_ATTESTED or await self.store.submission(block_id=block_id):
            return RELAYED
        return UNTRUSTED

    async def _observe(self, row: MessageRow) -> _Obs | None:
        body = row.json if isinstance(row.json, dict) else None
        if body is None:
            return None
        ie, sc = self._subject(row.tag, row.kind, row.ie_id, body)
        kind = row.kind
        if kind == SCORE_KIND:
            value = _score(body.get("score"))
            if ie is None or value is None:
                return None
        elif kind == ORCHESTRATOR_KIND or row.tag in self.cfg.security_tags:
            if ie is None:
                return None
        elif kind in LLO_KINDS:
            if sc is None:
                return None
        else:
            return None
        level = await self._trust(row.block_id, row.verdict, row.tag, row.iss)
        w = self.cfg.window_ms
        at = _msg_time(await self.store.get_message(row.block_id), w) or _msg_time(row, w)
        obs = _Obs(row.block_id, self._keys(ie, sc), at or self._now(), "alert", level,
                   ie_id=ie or self._host(sc),
                   detail={"kind": kind, "tag": row.tag, "verdict": row.verdict,
                           "trust": level},
                   position=None if row.ms_index is None else (row.ms_index, row.wf_index or 0))
        if level == UNTRUSTED:
            return None  # counts only through the alert raised about it
        if kind == SCORE_KIND:
            return await self._score_obs(obs, row, ie, value)
        if kind == ORCHESTRATOR_KIND:
            code = body.get("errorCode")
            obs.detail["errorCode"] = code
            if _is_error(code):
                obs.role, obs.opens, obs.severity = "security", True, "medium"
                obs.title = f"Self-orchestrator error {_label(str(code), 40)} on {ie}"
            elif obs.proven:
                obs.role = "remediation"
            else:
                return None  # a relayed all-clear remediates nothing
        elif kind in LLO_KINDS:
            event, host = body.get("event"), self._host(sc)
            obs.role = "deployment"
            obs.detail.update(event=event, serviceComponentId=sc, lloId=body.get("lloId"),
                              host=host)
            if isinstance(event, str) and event.strip().lower() == LLO_FAILED:
                obs.opens, obs.severity = True, "medium"
                obs.title = f"Service component {sc} failed" + (f" on {host}" if host else "")
            elif not obs.proven:
                return None  # relayed: only as a trigger
        else:  # security tag
            obs.role, obs.opens, obs.severity = "security", True, "high"
            obs.title = f"Security notification for {ie}"
        return obs

    async def _score_obs(self, obs: _Obs, row: MessageRow, ie: str,
                         value: float) -> _Obs | None:
        """A drop (a trigger), a proven routine score (may close by recovery), or nothing."""
        obs.role, obs.score = "score", value
        obs.detail["score"] = value
        prev = await self.store.trusted_previous_score(
            ie, relayed=not obs.proven, before=obs.position, exclude_block_id=row.block_id,
            **self._score_writers(row.tag))
        if prev is not None:
            obs.detail.update(previousScore=prev["score"],
                              previousBlockId=_hex(prev["block_id"]))
            if prev["score"] - value >= self.cfg.drop_threshold - EPS:
                obs.role, obs.opens, obs.severity = "trust-drop", True, "high"
                obs.title = f"Trust score of {ie} dropped {prev['score']:.2f} -> {value:.2f}"
                obs.baseline = (prev["score"], bytes(prev["block_id"]))
                return obs
        return obs if obs.proven else None

    def _subject(self, tag: str | None, kind: str | None, ie_id: str | None,
                 body: dict | None) -> tuple[str | None, str | None]:
        """(IE id, service component id) a message is about, sanitised."""
        ie = ie_id
        if ie is None and body is not None and (kind == ORCHESTRATOR_KIND
                                                or tag in self.cfg.security_tags):
            raw = body.get("infrastructureElementId", body.get("ieId"))
            ie = ie_id_of(raw.strip()) if isinstance(raw, str) and raw.strip() else None
        sc = body.get("serviceComponentId") if body is not None and kind in LLO_KINDS else None
        sc = _ident(sc) if isinstance(sc, str) and sc.strip() else None
        return (_ident(ie) if ie else None), sc

    def _score_writers(self, tag: str | None) -> dict[str, Any]:
        """Which earlier scores may serve as the reference a score is compared with: the
        same writers and signature rule the policy sets for the tag."""
        rule = self.policy.tags.get(tag or SCORE_KIND, self.policy.default)
        return {"issuers": None if "*" in rule.allowed else list(rule.allowed),
                "unsigned": not (rule.require_signature and not rule.legacy_grace)}

    def _host(self, sc: str | None) -> str | None:
        return None if sc is None else self._hosts.get(component_key(sc))

    def _resolvable(self, ie: str) -> bool:
        """An IE Orion lists (as an InfrastructureElement or as a component's host)."""
        known = self._known_ies
        return known is not None and ie in known

    def _keys(self, ie: str | None, sc: str | None, iss: str | None = None) -> set[str]:
        keys = set()
        if ie:
            keys.add(f"ie:{ie}")
        if sc:
            keys.add(f"sc:{_ident(component_key(sc))}")
            host = self._host(sc)
            if host:
                keys.add(f"ie:{host}")
        if not keys and iss:
            keys.add(f"iss:{_ident(iss)}")
        return keys

    # -- one alert ------------------------------------------------------------------------------

    async def _alert(self, a: dict, step: _Step) -> None:
        if await self.store.incident_alert_linked(a["id"]):
            return
        bid = None if a["block_id"] is None else bytes(a["block_id"])
        if bid is not None:
            holders = await self.store.incidents_with_block(bid)
            if holders:
                if a["rule"] in DISTRUST_RULES:  # found after the block counted
                    for inc in holders:
                        await self._revoke(inc, bid, str(a["rule"]), step)
                await self._link(holders[0], a, step)
                return
        msg = await self.store.get_message(bid) if bid is not None else None
        rule = str(a["rule"])
        alert_ie = _ident(a["ie_id"]) if isinstance(a["ie_id"], str) and a["ie_id"] else None
        witnessed = False
        block_level = UNTRUSTED
        if msg is not None and bid is not None:
            block_level = await self._trust(bid, msg["verdict"], msg["tag"], msg["iss"])
        if rule in INTEGRITY_RULES:  # about the explorer's own records: shapes nothing
            level, witnessed, opens = UNTRUSTED, True, True
            keys = {f"ie:{alert_ie}"} if alert_ie else {LEDGER}
            ie = alert_ie
        else:
            level = block_level
            if level == UNTRUSTED and rule not in ATTACK_RULES:
                return  # stays in /alerts
            body = msg["json"] if msg is not None and isinstance(msg["json"], dict) else None
            ie, sc = self._subject(msg and msg["tag"], msg and msg["kind"],
                                   alert_ie or (msg and msg["ie_id"]), body)
            keys = self._keys(ie, sc, msg and msg["iss"])
            if not keys:
                return
            opens = level != UNTRUSTED
            host = self._host(sc)
            target = host if ie is None else ie
            # Orion's component hosts are part of the IEs it knows (_refresh_orion)
            if level == UNTRUSTED and rule in ATTACK_RULES and target and self._resolvable(target):
                # an attack on the record of an IE Orion knows
                keys, opens, witnessed = {f"ie:{target}"}, True, True
            ie = ie or host
        label = RULE_TITLES.get(rule, _label(rule, 40))
        where = f"on {ie}" if ie else (f"in block {_hex(bid)[:12]}..." if bid else "")
        at = _msg_time(msg, self.cfg.window_ms) or _int(a["ts"]) or self._now()
        obs = _Obs(bid, keys, at, "alert",
                   level, opens=opens, witnessed=witnessed, severity=a["severity"], ie_id=ie,
                   title=f"{label} {where}".strip() + f" ({rule})" * (label != rule),
                   detail={"rule": rule, "alertId": a["id"], "trust": block_level,
                           "reason": _clean_value((a["evidence"] or {}).get("reason"))},
                   alert=a)
        if msg is not None and msg["ms_index"] is not None:
            obs.position = (msg["ms_index"], msg["wf_index"] or 0)
        await self._correlate(obs, step)

    async def _link(self, inc: dict, a: dict, step: _Step) -> None:
        """Join an alert to the incident its block is in; reported unless the block joined in
        this very step and the severity stays. An attack or integrity alert counts as
        activity of the incident only as far as the block itself does: freely for a proven
        block, capped for a relayed one, not at all for evidence (an `alert` event)."""
        if not await self.store.link_incident_alert(a["id"], inc["id"], self._now()):
            return
        fields: dict[str, Any] = {}
        sev = _max_sev(inc["severity"], a["severity"])
        if sev != inc["severity"]:
            fields["severity"] = sev
        at = inc.get("event_at_ms")
        mode = self._holder_mode(inc)
        if (a["rule"] in ATTACK_RULES | INTEGRITY_RULES and inc["status"] == OPEN and at
                and mode is not None):
            fields.update(self._extension(inc, at, mode))
        if fields:
            await self.store.update_incident(inc["id"], **fields)
            inc.update(fields)
        joined_now = a["block_id"] is not None and bytes(a["block_id"]) in step.attached
        if joined_now and "severity" not in fields:
            return
        step.changes.append(_change("updated", inc, block_id=a["block_id"], rule=a["rule"]))

    @staticmethod
    def _holder_mode(inc: dict) -> str | None:
        """How far the event a block already has in an incident may move it, from the trust
        recorded when it joined: PROVEN, RELAYED, or None (evidence, untrusted, unknown)."""
        if inc.get("event_role") == "alert":
            return None
        detail = inc.get("event_detail")
        trust = detail.get("trust") if isinstance(detail, dict) else None
        return trust if trust in (PROVEN, RELAYED) else None

    async def _revoke(self, inc: dict, bid: bytes, rule: str, step: _Step) -> None:
        """A block an incident counted turned out SHADOW: its event becomes evidence only,
        an incident it closed reopens, and if it was a proven drop the recovery target and
        low score are recomputed from the proven drops that remain. Keys and the latest event
        time are not rewound (they only keep the incident wider and open longer)."""
        was = await self.store.revoke_incident_event(inc["id"], bid, rule.lower())
        if was is None:
            return
        step.attached.add(bid)  # reported here; the alert's own link needs no second line
        step.changes.append(_change("revoked", inc, block_id=bid, role=was, rule=rule))
        closed_by = inc["closed_by"]
        if (inc["status"] == CLOSED_RECOVERED and closed_by is not None
                and bytes(closed_by) == bid and await self.store.reopen_incident(inc["id"], bid)):
            inc.update(status=OPEN, closed_at_ms=None, closed_by=None)
            step.changes.append(_change("reopened", inc, block_id=bid, rule=rule))
        detail = inc.get("event_detail") or {}
        if was == "trust-drop" or (was == "trigger" and detail.get("as") == "trust-drop"):
            drops = await self.store.incident_proven_drops(inc["id"])
            scores = [d["detail"].get("score") for d in drops]
            fields: dict[str, Any] = {"low_score": min(
                (v for v in scores if isinstance(v, int | float)), default=None)}
            first = drops[0]["detail"] if drops else {}
            prev, prev_id = first.get("previousScore"), first.get("previousBlockId")
            if isinstance(prev, int | float) and isinstance(prev_id, str):
                fields["baseline_score"] = float(prev)
                fields["baseline_block_id"] = bytes.fromhex(prev_id.removeprefix("0x"))
            await self.store.update_incident(inc["id"], **fields)
            inc.update(fields)

    # -- correlation ----------------------------------------------------------------------------

    def _pick(self, candidates: list[dict], at: int) -> dict | None:
        w = self.cfg.window_ms
        for inc in candidates:
            last = inc["last_event_ms"] or inc["opened_at_ms"]
            if inc["opened_at_ms"] - w <= at <= last + w:
                return inc
        return None

    async def _correlate(self, obs: _Obs, step: _Step) -> None:
        if (obs.block_id is not None and obs.alert is None
                and await self.store.incidents_with_block(obs.block_id)):
            return  # seen before (a reprocessed milestone)
        candidates = await self.store.open_incidents(sorted(obs.keys))
        if obs.role == "score":
            await self._recovery(obs, candidates, step)
            return
        inc = self._pick(candidates, obs.at_ms)
        if inc is None:
            if obs.opens:
                await self._open(obs, step)
            return
        await self._attach(inc, obs, step)

    async def _baseline(self, ie: str, obs: _Obs) -> tuple[float, bytes] | None:
        if obs.baseline is not None:
            return obs.baseline
        prev = await self.store.trusted_previous_score(
            ie, relayed=False, before=obs.position, exclude_block_id=obs.block_id or b"",
            **self._score_writers(SCORE_KIND))
        return None if prev is None else (prev["score"], bytes(prev["block_id"]))

    async def _open(self, obs: _Obs, step: _Step) -> None:
        base = await self._baseline(obs.ie_id, obs) if obs.ie_id and obs.proven else None
        low = obs.score if obs.proven and obs.role == "trust-drop" else None
        inc = {"status": OPEN, "severity": obs.severity or "low", "ie_id": obs.ie_id,
               "title": _label(obs.title or "Incident")}
        inc["id"] = await self.store.put_incident(
            opened_at_ms=obs.at_ms, severity=inc["severity"], title=inc["title"],
            ie_id=obs.ie_id, keys=sorted(obs.keys), last_event_ms=obs.at_ms,
            anchor_ms=obs.at_ms, baseline_score=base and base[0],
            baseline_block_id=base and base[1], low_score=low)
        if obs.block_id is not None:
            await self.store.attach_incident_event(
                inc["id"], obs.block_id, "trigger", at_ms=obs.at_ms,
                detail=_clean_value({"as": obs.role, **obs.detail}))
            step.attached.add(obs.block_id)
        if obs.alert is not None:
            await self.store.link_incident_alert(obs.alert["id"], inc["id"], self._now())
        step.changes.append(_change("opened", inc, block_id=obs.block_id, role="trigger",
                                    at_ms=obs.at_ms, rule=obs.detail.get("rule")))

    async def _attach(self, inc: dict, obs: _Obs, step: _Step) -> None:
        added = False
        if obs.block_id is not None:
            added = await self.store.attach_incident_event(
                inc["id"], obs.block_id, obs.role, at_ms=obs.at_ms,
                detail=_clean_value(obs.detail))
            if added:
                step.attached.add(obs.block_id)
        fields: dict[str, Any] = {}
        sev = _max_sev(inc["severity"], obs.severity)
        if sev != inc["severity"]:
            fields["severity"] = sev
        mode = obs.level if obs.level != UNTRUSTED else (WITNESSED if obs.witnessed else None)
        if mode is not None:
            fields.update(self._extension(inc, obs.at_ms, mode))
        if obs.proven:  # only proven content shapes an incident
            keys = set(inc["keys"]) | obs.keys
            if keys != set(inc["keys"]):
                fields["keys"] = sorted(keys)
            if obs.ie_id and inc["ie_id"] is None:
                fields["ie_id"] = obs.ie_id
            ie = fields.get("ie_id", inc["ie_id"])
            if ie and inc["baseline_score"] is None and f"ie:{ie}" in obs.keys:
                base = await self._baseline(ie, obs)
                if base is not None:
                    fields["baseline_score"], fields["baseline_block_id"] = base
            if obs.role == "trust-drop" and obs.score is not None:
                low = inc["low_score"]
                if low is None:  # the first drop: recovery means back to where it fell from
                    fields["low_score"] = obs.score
                    if obs.baseline is not None:
                        fields["baseline_score"], fields["baseline_block_id"] = obs.baseline
                elif obs.score < low:
                    fields["low_score"] = obs.score
        if fields:
            await self.store.update_incident(inc["id"], **fields)
            inc.update(fields)
        if obs.alert is not None:
            await self.store.link_incident_alert(obs.alert["id"], inc["id"], self._now())
        if added:
            step.changes.append(_change("attached", inc, block_id=obs.block_id, role=obs.role,
                                        at_ms=obs.at_ms, rule=obs.detail.get("rule")))
        elif obs.block_id is None and obs.alert is not None:
            step.changes.append(_change("updated", inc, rule=obs.detail.get("rule")))

    def _extension(self, inc: dict, at: int, mode: str) -> dict[str, int]:
        """How an event at `at` moves the incident's latest event: freely for PROVEN events
        (which also move the anchor), at most one window past the anchor for RELAYED events
        and WITNESSED alerts."""
        fields: dict[str, int] = {}
        anchor = inc["anchor_ms"] or inc["opened_at_ms"]
        if mode == PROVEN:
            if at > anchor:
                fields["anchor_ms"] = at
        else:
            at = min(at, anchor + self.cfg.window_ms)
        if at > (inc["last_event_ms"] or 0):
            fields["last_event_ms"] = at
        return fields

    async def _recovery(self, obs: _Obs, candidates: list[dict], step: _Step) -> None:
        """A routine proven score. An incident that saw a trust drop (`low_score` set) closes
        when a PROVEN score is back at the level the first drop fell from; otherwise only how
        low it went is kept."""
        if not obs.proven or obs.score is None:
            return  # only a proven score may close or lower anything
        for inc in candidates:
            if f"ie:{obs.ie_id}" not in inc["keys"] or obs.at_ms < inc["opened_at_ms"]:
                continue
            base, low = inc["baseline_score"], inc["low_score"]
            if base is not None and low is not None and obs.score >= base - EPS:
                if await self.store.attach_incident_event(
                        inc["id"], obs.block_id, "remediation", at_ms=obs.at_ms,
                        detail=_clean_value({**obs.detail, "baselineScore": base})):
                    step.attached.add(obs.block_id)
                    step.changes.append(_change("attached", inc, block_id=obs.block_id,
                                                role="remediation", at_ms=obs.at_ms))
                ext = self._extension(inc, obs.at_ms, PROVEN)
                if ext:
                    await self.store.update_incident(inc["id"], **ext)
                if await self.store.close_incident(inc["id"], CLOSED_RECOVERED,
                                                   closed_at_ms=obs.at_ms,
                                                   closed_by=obs.block_id):
                    inc["status"] = CLOSED_RECOVERED
                    step.changes.append(_change("closed", inc, block_id=obs.block_id,
                                                at_ms=obs.at_ms))
            elif low is not None and obs.score is not None and obs.score < low:
                await self.store.update_incident(inc["id"], low_score=obs.score)

    # -- periodic steps -------------------------------------------------------------------------

    async def _scan_alerts(self, step: _Step, now_ms: int) -> None:
        """Every critical or high alert logged since the last pass, from the events log:
        every alert the rules and the validator store is logged there, in commit order."""
        cursor = _int(await self.store.get_rule_state(ALERT_CURSOR)) or 0
        rows = await self.store.events_of_type_after(events.ALERT, cursor,
                                                     self.cfg.alert_batch)
        for ev in rows:
            p = ev["payload"] if isinstance(ev["payload"], dict) else {}
            if p.get("severity") not in TRIGGER_SEVERITIES or not isinstance(p.get("rule"), str):
                continue
            try:
                bid = None if p.get("blockId") is None else from_hex(p["blockId"])
            except (TypeError, ValueError):
                continue
            a = await self.store.alert_by_key(p["rule"], bid, p.get("ieId"), p.get("dedupeKey"))
            if a is not None:
                await self._alert(a, step)
        if rows:
            await self.store.set_rule_state(ALERT_CURSOR, rows[-1]["id"], at_ms=now_ms)

    async def _quiet(self, step: _Step, now_ms: int) -> None:
        ref = now_ms
        latest = await self.store.latest_milestone_ts()
        if latest is not None:
            ref = min(now_ms, latest * 1000)
        for inc in await self.store.idle_incidents(ref - self.cfg.quiet_close_ms):
            if await self.store.close_incident(inc["id"], CLOSED_QUIET, closed_at_ms=now_ms):
                inc["status"] = CLOSED_QUIET
                step.changes.append(_change("closed", inc, at_ms=now_ms))

    # -- plumbing -------------------------------------------------------------------------------

    async def _emit(self, step: _Step) -> None:
        for c in step.changes:
            await self.store.emit(events.INCIDENT, c)

    async def _refresh_orion(self) -> None:
        """Reload Orion's IE ids and component -> IE map when older than `orion_ttl_s`. Best
        effort, never inside a transaction: a failure keeps the previous answer and is
        reported as `incident-orion: unreachable`. Ids are sanitised and cut like message
        ids, so they line up with what messages name."""
        if self.orion is None or time.monotonic() - self._orion_at < self.cfg.orion_ttl_s:
            return
        self._orion_at = time.monotonic()
        cap, budget = self.cfg.orion_max_entries, self.cfg.orion_max_bytes
        try:
            ies = await asyncio.wait_for(self.orion.ie_entities(max_bytes=budget),
                                         self.cfg.orion_timeout_s)
            hosts = await asyncio.wait_for(
                self.orion.service_component_hosts(max_bytes=budget), self.cfg.orion_timeout_s)
            if len(ies) > cap or len(hosts) > cap:
                raise ValueError(f"more than {cap} entities")
        except Exception as exc:  # noqa: BLE001 - Orion only refines correlation
            log.warning("Orion IEs and components not refreshed: %s: %s",
                        type(exc).__name__, exc)
            with contextlib.suppress(Exception):
                await self._set_status(ORION_STATUS, "unreachable",
                                       f"{type(exc).__name__}: {exc}; keeping the last answer")
            return
        self._hosts = {component_key(_ident(k)): _ident(ie_id_of(v))
                       for k, v in hosts.items()
                       if isinstance(k, str) and k.strip() and isinstance(v, str) and v.strip()}
        known = {_ident(i.ie_id) for i in ies if isinstance(getattr(i, "ie_id", None), str)}
        self._known_ies = frozenset(known | set(self._hosts.values()))
        with contextlib.suppress(Exception):
            await self._set_status(ORION_STATUS, "ok")

    def _event_view(self, r: dict) -> dict:
        bid = _hex(r["block_id"])
        return {"blockId": bid, "role": r["role"], "atMs": r["at_ms"], "tag": r["tag"],
                "kind": r["kind"], "verdict": r["verdict"], "status": r["status"],
                "msIndex": r["ms_index"], "ieId": r["ie_id"], "iss": r["iss"],
                "indexed": r["indexed"], "detail": r["detail"], "proof": f"/proofs/{bid}"}

    async def _init_cursor(self) -> None:
        """Where delivery resumes: the persisted cursor, or (first start) the current end of
        the events log, so history is not replayed. Saved by the next flush."""
        if self.publisher is None or self._cursor is not None:
            return
        stored = _int(await self.store.get_rule_state(PUBLISH_CURSOR))
        if stored is None:
            self._cursor = await self.store.last_event_id()
        else:
            self._cursor = self._saved_cursor = stored

    async def _save_cursor(self) -> None:
        if self._cursor != self._saved_cursor:
            await self.store.set_rule_state(PUBLISH_CURSOR, self._cursor)
            self._saved_cursor = self._cursor

    async def _flush(self) -> int:
        await self._init_cursor()
        assert self.publisher is not None and self._cursor is not None
        sent = 0
        while True:
            rows = await self.store.events_of_type_after(events.INCIDENT, self._cursor,
                                                         self.cfg.publish_batch)
            for r in rows:
                payload = dict(r["payload"])
                sev = payload.get("severity")
                topic = f"{self.cfg.mqtt_topic_prefix}/{sev if sev in SEV_RANK else 'unknown'}"
                body = json.dumps({**payload, "eventId": r["id"]}, separators=(",", ":"),
                                  ensure_ascii=False).encode("utf-8", "backslashreplace")
                try:
                    await asyncio.wait_for(self.publisher.publish(topic, body),
                                           self.cfg.publish_timeout_s)
                except Exception as exc:  # noqa: BLE001 - broker down or slow: retry later
                    log.warning("incident alert not published (%s): %s: %s", topic,
                                type(exc).__name__, exc)
                    await self._save_cursor()
                    await self._set_status(MQTT_STATUS, "unreachable",
                                           f"{type(exc).__name__}: {exc}")
                    return sent
                self._cursor = r["id"]
                sent += 1
            await self._save_cursor()
            if len(rows) < self.cfg.publish_batch:
                break
        await self._set_status(MQTT_STATUS, "ok")
        return sent

    async def _failed(self, name: str, exc: Exception) -> None:
        log.error("incident engine step %s failed", name, exc_info=exc)
        self._last_error_ms = self._now()
        try:
            await self.store.set_service_status(
                ENGINE_STATUS, "error", detail=_clean_text(f"{name}: {type(exc).__name__}: {exc}"),
                at_ms=self._last_error_ms)
            self._status[ENGINE_STATUS] = "error"
        except Exception:  # reporting must not raise either
            log.exception("could not record the incident engine failure")

    async def _set_status(self, name: str, status: str, detail: str | None = None) -> None:
        if self._status.get(name) == status:
            return
        await self.store.set_service_status(
            name, status, detail=None if detail is None else _clean_text(detail),
            at_ms=self._now())
        self._status[name] = status


class CorrelatedRules:
    """A RulesEngine that also feeds an IncidentEngine: give it to the indexer where the rules
    engine went. Returns the rules' alerts unchanged; everything else is the rules engine's."""

    def __init__(self, rules: Any, incidents: IncidentEngine) -> None:
        self.rules = rules
        self.incidents = incidents

    async def on_message(self, row: MessageRow) -> list[Alert]:
        alerts = self.rules.on_message(row)
        if inspect.isawaitable(alerts):
            alerts = await alerts
        await self.incidents.on_message(row)
        return alerts

    async def periodic(self, *, now_ms: int) -> list[Alert]:
        alerts = await self.rules.periodic(now_ms=now_ms)
        await self.incidents.periodic(now_ms=now_ms)
        return alerts

    def __getattr__(self, name: str) -> Any:
        return getattr(self.rules, name)


class MqttAlertPublisher:
    """AlertPublisher over one aiomqtt connection, opened on first use and reopened after a
    failure. `url` is `mqtt://[user:password@]host[:port]`."""

    def __init__(self, url: str, *, client_id: str = "witness-indexer-alerts",
                 timeout_s: float = 5.0) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("mqtt", "tcp"):
            raise ValueError(f"unsupported MQTT URL scheme: {parts.scheme!r}")
        self._params = {
            "hostname": parts.hostname or "127.0.0.1",
            "port": parts.port or 1883,
            "username": unquote(parts.username) if parts.username else None,
            "password": unquote(parts.password) if parts.password else None,
            "identifier": client_id,
            "timeout": timeout_s,
        }
        self._timeout = timeout_s
        self._stack: AsyncExitStack | None = None
        self._client: Any = None
        self._lock = asyncio.Lock()

    async def publish(self, topic: str, payload: bytes) -> None:
        async with self._lock:
            try:
                if self._client is None:
                    import aiomqtt

                    stack = AsyncExitStack()
                    client = await stack.enter_async_context(aiomqtt.Client(**self._params))
                    self._stack, self._client = stack, client
                await self._client.publish(topic, payload, qos=1, timeout=self._timeout)
            except BaseException:
                await self._reset()
                raise

    async def _reset(self) -> None:
        stack, self._stack, self._client = self._stack, None, None
        if stack is not None:
            with contextlib.suppress(Exception):
                await stack.aclose()

    async def aclose(self) -> None:
        async with self._lock:
            await self._reset()
