"""Incident Explorer: correlated trust events on one timeline, each verifiable by its block id.

aeriOS writes the pieces of a security story to the Tangle from different components: the
Trust Manager lowers an IE's `trust.score` after Suricata alerts, the self-orchestrator
reports an `errorCode` for the IE, an LLO reports "Service component failed" for a component
running on it. The engine groups them into incidents.

Triggers (a message or alert that may open an incident):

- a `trust.score` that drops by at least `drop_threshold` below the IE's previous PROVEN score;
- a `self-orchestrator` message with a non-zero, non-empty `errorCode`;
- an LLO (`LLO-K8s` / `LLO-Docker`) "Service component failed";
- a message on one of `security_tags` naming an IE (e.g. `self-security`);
- a critical or high alert on a block (FORGED, REPLAY, CHAIN_FORK, CONTENT_MISMATCH, ...).
  Alerts about the explorer's own records (`INTEGRITY_RULES`: DB_TAMPER, MISSING_IN_DB,
  ANCHOR_MISMATCH, ...) form a `ledger` incident unless they name an IE.

Correlation: an incident has keys (`ie:<IE id>`, `sc:<service component>`, `iss:<issuer>`,
`ledger`). An event joins the open incident it shares a key with when it happened within
`window_ms` of that incident's latest event; otherwise a trigger opens a new incident. An LLO
report joins the incident of the IE its component runs on: the component -> IE relationship
comes from Orion's ServiceComponent entities (fetched only outside a database transaction,
2 s budget, cached), else the component id alone is the key. The LLO's k8s resource name
(`urn-ngsi-ld-service-<id>-component-<name>`) and the Orion entity id are lined up.

Trust: only PROVEN (producer-signed or relay-attested) or relay-routed unsigned events (a
submission names the block) without a SHADOW alert may open an incident or add keys to it.
Anything else (FORGED, REPLAY, written around the relay, ...) joins an open incident as
`alert` evidence only: it never opens, closes, extends or remediates one, so an attacker can
neither invent an incident nor write its closure.

Every event carries its block id and a role: `trigger` (the event that opened the incident),
`trust-drop`, `security`, `deployment` (LLO reports), `remediation` (a cleared self-
orchestrator code, the recovered trust score) or `alert`. An incident's severity is the
highest of its members'.

Close: `closed:recovered` when, after a trust drop, a PROVEN trust.score is back to (or above)
the level the incident's first drop fell from; `closed:quiet` after `quiet_close_ms` with no
new event (measured on the ledger clock, so a backfill does not close incidents early). An
incident without a trust drop (an orchestrator error alone) closes quietly.

Delivery: each change (opened / attached / updated / closed) is emitted as an `incident` event
in the same transaction. A configured `AlertPublisher` sends committed ones, as compact JSON,
to MQTT `witness/alerts/{severity}` (QoS 1): `flush()` reads the events log from a persisted
cursor, so nothing is published for a transaction that rolls back and a broker outage only
delays alerts. Publishing never breaks indexing (`alerts-mqtt: ok | unreachable` in
`Store.stats()`).

Robustness, as in rules.py: text from messages is sanitised before it is stored or published,
every step runs in a savepoint, a failure is logged and reported (`incident-engine: error`;
`incidents` itself is the table count in `Store.stats()`) and never raised into the caller's
transaction, and no HTTP happens inside a transaction.

Wiring (indexer `main.py`):

    incidents = IncidentEngine(store, orion, IncidentConfig(),
                               MqttAlertPublisher(args.mqtt) if args.mqtt else None)
    rules = CorrelatedRules(rules, incidents)     # Indexer(rules=...), Every(... periodic)
    services.append(("alerts-mqtt", incidents.run_publisher, incidents.stop_publisher))
    closers.append(incidents.aclose)

`CorrelatedRules` is a drop-in for the RulesEngine: it returns the rules' alerts and runs the
incident engine after them, per message (inside the milestone transaction) and per periodic
pass (which also picks up the alerts the validator and the periodic rules raise).
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

from witness_core import verdicts as V
from witness_core.ids import to_hex

from . import events
from .orion import OrionClient, ie_id_of
from .rules import PROVEN, _clean_text
from .rules import _clean as _clean_value
from .store import Alert, MessageRow, Store

__all__ = ["AlertPublisher", "CorrelatedRules", "IncidentConfig", "IncidentEngine",
           "MqttAlertPublisher", "component_key"]

log = logging.getLogger(__name__)

SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
TRIGGER_SEVERITIES = ["critical", "high"]
# Alerts about the explorer's own records rather than about what a writer claimed.
INTEGRITY_RULES = frozenset({"MISSING_IN_DB", "DB_TAMPER", "ANCHOR_MISMATCH",
                             "CONTENT_MISMATCH", "NOT_FOUND", "ORPHANED"})
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
MQTT_STATUS = "alerts-mqtt"
ALERT_CURSOR = "incidents.alert_cursor"
PUBLISH_CURSOR = "incidents.mqtt_cursor"
# Alerts are re-read this many ids behind the cursor: an alert whose transaction commits
# after a later one would otherwise be skipped.
ALERT_LOOKBACK = 50
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


def _msg_time(m: dict | MessageRow | None) -> int | None:
    """When a message happened: relay receipt, else confirmation, else milestone time."""
    if m is None:
        return None
    get = m.get if isinstance(m, dict) else (lambda k: getattr(m, k, None))
    for k in ("received_at_ms", "confirmed_at_ms"):
        v = get(k)
        if isinstance(v, int) and v > 0:
            return v
    ts = get("ts")
    return ts * 1000 if isinstance(ts, int) and ts > 0 else None


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
    trusted: bool                 # proven or relay-routed, no SHADOW
    opens: bool = False           # a trigger
    severity: str | None = None
    title: str = ""
    ie_id: str | None = None
    detail: dict = field(default_factory=dict)
    score: float | None = None
    proven_score: bool = False    # a PROVEN trust.score: may close an incident by recovery
    baseline: tuple[float, bytes] | None = None
    position: tuple[int, int] | None = None
    alert: dict | None = None


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
                 now_ms: Callable[[], int] | None = None) -> None:
        self.store = store
        self.orion = orion
        self.cfg = cfg or IncidentConfig()
        self.publisher = publisher
        self._now = now_ms or (lambda: int(time.time() * 1000))
        self._hosts: dict[str, str] = {}  # component_key -> IE id
        self._hosts_at = -math.inf
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
                await self._refresh_hosts()
            async with self.store.transaction(), self.store.savepoint():
                await self._init_cursor()
                changes = await self._message(row)
        except Exception as exc:  # noqa: BLE001 - the indexer goes on whatever a message does
            changes = []
            await self._failed("message", exc)
        await self.flush()
        return changes

    async def periodic(self, *, now_ms: int) -> list[dict]:
        """Alerts raised since the last pass (validator, periodic rules), quiet closes, and
        delivery of pending alerts. Returns the incident changes."""
        changes: list[dict] = []
        if not self.store.in_transaction():
            await self._refresh_hosts()
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
        await self.flush()
        last = self._last_error_ms
        if last is None or self._now() - last > self.cfg.error_hold_s * 1000:
            with contextlib.suppress(Exception):
                await self._set_status(ENGINE_STATUS, "ok")
        return changes

    async def timeline(self, incident_id: int) -> dict | None:
        """The incident and its events in time order. Each event names its block, the
        message's verdict and its lifecycle status, and the proof to check it against
        (`/proofs/{blockId}`)."""
        inc = await self.store.incident(incident_id)
        if inc is None:
            return None
        rows = await self.store.incident_timeline(incident_id)
        alerts = await self.store.incident_alerts(incident_id)
        return {
            "incident": {
                "id": inc["id"], "title": inc["title"], "severity": inc["severity"],
                "status": inc["status"], "ieId": inc["ie_id"], "keys": list(inc["keys"]),
                "openedAtMs": inc["opened_at_ms"], "closedAtMs": inc["closed_at_ms"],
                "lastEventMs": inc["last_event_ms"], "baselineScore": inc["baseline_score"],
                "lowScore": inc["low_score"], "closedBy": _hex(inc["closed_by"]),
            },
            "events": [self._event_view(r) for r in rows],
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
        """Deliver alerts as their transactions commit (polls every `publish_poll_s`)."""
        self._stopping = False
        self._wake = asyncio.Event()
        while not self._stopping:
            await self.flush()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), self.cfg.publish_poll_s)
            self._wake.clear()

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

    async def _trust(self, block_id: bytes, verdict: str | None) -> str:
        """`proven`, `relayed` (unsigned, received through the Messages API) or `untrusted`."""
        if verdict in PROVEN:
            level = "proven"
        elif verdict == V.UNSIGNED_LEGACY and await self.store.submission(block_id=block_id):
            level = "relayed"
        else:
            return "untrusted"
        if await self.store.has_alert("SHADOW", block_id=block_id):
            return "untrusted"
        return level

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
        trust = await self._trust(row.block_id, row.verdict)
        at = _msg_time(await self.store.get_message(row.block_id)) or _msg_time(row)
        obs = _Obs(row.block_id, self._keys(ie, sc), at or self._now(), "alert",
                   trusted=trust != "untrusted", ie_id=ie or self._host(sc),
                   detail={"kind": kind, "tag": row.tag, "verdict": row.verdict,
                           "trust": trust},
                   position=None if row.ms_index is None else (row.ms_index, row.wf_index or 0))
        if not obs.trusted:
            return obs  # evidence only
        if kind == SCORE_KIND:
            await self._score_obs(obs, row, ie, value, trust)
        elif kind == ORCHESTRATOR_KIND:
            code = body.get("errorCode")
            obs.detail["errorCode"] = code
            if _is_error(code):
                obs.role, obs.opens, obs.severity = "security", True, "medium"
                obs.title = f"Self-orchestrator error {_label(str(code), 40)} on {ie}"
            else:
                obs.role = "remediation"
        elif kind in LLO_KINDS:
            event, host = body.get("event"), self._host(sc)
            obs.role = "deployment"
            obs.detail.update(event=event, serviceComponentId=sc, lloId=body.get("lloId"),
                              host=host)
            if isinstance(event, str) and event.strip().lower() == LLO_FAILED:
                obs.opens, obs.severity = True, "medium"
                obs.title = f"Service component {sc} failed" + (f" on {host}" if host else "")
        else:  # security tag
            obs.role, obs.opens, obs.severity = "security", True, "high"
            obs.title = f"Security notification for {ie}"
        return obs

    async def _score_obs(self, obs: _Obs, row: MessageRow, ie: str, value: float,
                         trust: str) -> None:
        obs.role, obs.score = "score", value
        obs.proven_score = trust == "proven"
        obs.detail["score"] = value
        prev = await self.store.previous_score(ie, list(PROVEN), obs.position, row.block_id)
        if prev is None:
            return
        obs.detail.update(previousScore=prev["score"], previousBlockId=_hex(prev["block_id"]))
        if prev["score"] - value >= self.cfg.drop_threshold - EPS:
            obs.role, obs.opens, obs.severity = "trust-drop", True, "high"
            obs.title = f"Trust score of {ie} dropped {prev['score']:.2f} -> {value:.2f}"
            obs.baseline = (prev["score"], bytes(prev["block_id"]))

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

    def _host(self, sc: str | None) -> str | None:
        return None if sc is None else self._hosts.get(component_key(sc))

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
                await self._link(holders[0], a, step)
                return
        msg = await self.store.get_message(bid) if bid is not None else None
        rule = str(a["rule"])
        alert_ie = _ident(a["ie_id"]) if isinstance(a["ie_id"], str) and a["ie_id"] else None
        if rule in INTEGRITY_RULES:
            trusted = True
            keys = {f"ie:{alert_ie}"} if alert_ie else {LEDGER}
            ie = alert_ie
        else:
            trusted = (msg is not None
                       and await self._trust(bid, msg["verdict"]) != "untrusted")  # type: ignore[arg-type]
            body = msg["json"] if msg is not None and isinstance(msg["json"], dict) else None
            ie, sc = self._subject(msg and msg["tag"], msg and msg["kind"],
                                   alert_ie or (msg and msg["ie_id"]), body)
            keys = self._keys(ie, sc, msg and msg["iss"])
            ie = ie or self._host(sc)
            if not keys:
                return
        label = RULE_TITLES.get(rule, _label(rule, 40))
        where = f"on {ie}" if ie else (f"in block {_hex(bid)[:12]}..." if bid else "")
        obs = _Obs(bid, keys, _msg_time(msg) or _int(a["ts"]) or self._now(), "alert",
                   trusted=trusted, opens=trusted, severity=a["severity"], ie_id=ie,
                   title=f"{label} {where}".strip() + f" ({rule})" * (label != rule),
                   detail={"rule": rule, "alertId": a["id"],
                           "reason": _clean_value((a["evidence"] or {}).get("reason"))},
                   alert=a)
        if msg is not None and msg["ms_index"] is not None:
            obs.position = (msg["ms_index"], msg["wf_index"] or 0)
        await self._correlate(obs, step)

    async def _link(self, inc: dict, a: dict, step: _Step) -> None:
        """Join an alert to an incident; reported unless its block joined in this very step
        and the severity stays."""
        if not await self.store.link_incident_alert(a["id"], inc["id"], self._now()):
            return
        sev = _max_sev(inc["severity"], a["severity"])
        if sev != inc["severity"]:
            await self.store.update_incident(inc["id"], severity=sev)
            inc["severity"] = sev
        elif a["block_id"] is not None and bytes(a["block_id"]) in step.attached:
            return
        step.changes.append(_change("updated", inc, block_id=a["block_id"], rule=a["rule"]))

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
            if obs.opens and obs.trusted:
                await self._open(obs, step)
            return
        await self._attach(inc, obs, step)

    async def _baseline(self, ie: str, obs: _Obs) -> tuple[float, bytes] | None:
        if obs.baseline is not None:
            return obs.baseline
        prev = await self.store.previous_score(ie, list(PROVEN), obs.position,
                                               obs.block_id or b"")
        return None if prev is None else (prev["score"], bytes(prev["block_id"]))

    async def _open(self, obs: _Obs, step: _Step) -> None:
        base = await self._baseline(obs.ie_id, obs) if obs.ie_id else None
        inc = {"status": OPEN, "severity": obs.severity or "low", "ie_id": obs.ie_id,
               "title": _label(obs.title or "Incident")}
        inc["id"] = await self.store.put_incident(
            opened_at_ms=obs.at_ms, severity=inc["severity"], title=inc["title"],
            ie_id=obs.ie_id, keys=sorted(obs.keys), last_event_ms=obs.at_ms,
            baseline_score=base and base[0], baseline_block_id=base and base[1],
            low_score=obs.score if obs.role == "trust-drop" else None)
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
        if obs.trusted:  # evidence an attacker wrote never shapes or prolongs an incident
            keys = set(inc["keys"]) | obs.keys
            if keys != set(inc["keys"]):
                fields["keys"] = sorted(keys)
            if obs.at_ms > (inc["last_event_ms"] or 0):
                fields["last_event_ms"] = obs.at_ms
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

    async def _recovery(self, obs: _Obs, candidates: list[dict], step: _Step) -> None:
        """A routine trusted score. An incident that saw a trust drop (`low_score` set) closes
        when a PROVEN score is back at the level the first drop fell from; otherwise only how
        low it went is kept."""
        for inc in candidates:
            if f"ie:{obs.ie_id}" not in inc["keys"] or obs.at_ms < inc["opened_at_ms"]:
                continue
            base, low = inc["baseline_score"], inc["low_score"]
            if (obs.proven_score and base is not None and low is not None
                    and obs.score >= base - EPS):
                if await self.store.attach_incident_event(
                        inc["id"], obs.block_id, "remediation", at_ms=obs.at_ms,
                        detail=_clean_value({**obs.detail, "baselineScore": base})):
                    step.attached.add(obs.block_id)
                    step.changes.append(_change("attached", inc, block_id=obs.block_id,
                                                role="remediation", at_ms=obs.at_ms))
                await self.store.update_incident(inc["id"], last_event_ms=max(
                    obs.at_ms, inc["last_event_ms"] or 0))
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
        cursor = _int(await self.store.get_rule_state(ALERT_CURSOR)) or 0
        rows = await self.store.alerts_after(max(0, cursor - ALERT_LOOKBACK),
                                             TRIGGER_SEVERITIES, self.cfg.alert_batch)
        for a in rows:
            await self._alert(a, step)
        if rows and rows[-1]["id"] > cursor:
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

    async def _refresh_hosts(self) -> None:
        """Reload the component -> IE map from Orion when it is older than `orion_ttl_s`.
        Best effort: a failure keeps the previous map."""
        fetch = getattr(self.orion, "service_component_hosts", None)
        if fetch is None or time.monotonic() - self._hosts_at < self.cfg.orion_ttl_s:
            return
        self._hosts_at = time.monotonic()
        try:
            hosts = await asyncio.wait_for(fetch(), self.cfg.orion_timeout_s)
        except Exception as exc:  # noqa: BLE001 - Orion only refines correlation
            log.warning("service component map not refreshed: %s: %s", type(exc).__name__, exc)
            return
        self._hosts = {component_key(k): _ident(ie_id_of(v)) for k, v in hosts.items()
                       if isinstance(k, str) and isinstance(v, str) and v}

    def _event_view(self, r: dict) -> dict:
        bid = _hex(r["block_id"])
        status = r["lifecycle_status"] or r["message_status"]
        if status is None and r["ms_index"] is not None:
            status = "CONFIRMED"  # in a milestone's cone, never seen through the relay
        return {"blockId": bid, "role": r["role"], "atMs": r["at_ms"], "tag": r["tag"],
                "kind": r["kind"], "verdict": r["verdict"], "status": status,
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
