import asyncio
import dataclasses
import itertools
import json
import os
import unicodedata
import uuid
from urllib.parse import urlsplit

import pytest
from witness_core import policy as writer_policy
from witness_core import schema
from witness_core import verdicts as V
from witness_core.ids import blake2b256, to_hex
from witness_indexer import events
from witness_indexer.incidents import (
    CorrelatedRules,
    IncidentConfig,
    IncidentEngine,
    MqttAlertPublisher,
    component_key,
)
from witness_indexer.orion import IE, OrionUnavailable
from witness_indexer.rules import SEVERITY
from witness_indexer.store import Alert, MessageRow, Store, Submission

URN = "urn:ngsi-ld:InfrastructureElement:"
IE_X = "MyDomain:fa163e5e25ef"
IE_Y = "MyDomain:fa163e5e25f0"
IE_Z = "Edge:001122334455"
SC = "urn:ngsi-ld:Service:0a1b:Component:web"
SC_K8S = "urn-ngsi-ld-service-0a1b-component-web"  # the LLO reports the k8s resource name
T0 = 1_791_280_000  # seconds
_blocks = itertools.count(1)


def row(tag: str, body: dict, *, ms: int, verdict: str = V.PRODUCER_SIGNED,
        ts: int | None = None) -> MessageRow:
    data = json.dumps(body).encode()
    c = schema.classify(tag, data)
    return MessageRow(
        block_id=blake2b256(data + next(_blocks).to_bytes(8, "big")), tag=tag, kind=c.kind,
        data=data, json=c.json, ie_id=c.ie_id, verdict=verdict, ms_index=ms, wf_index=0,
        ts=T0 + 30 * ms if ts is None else ts)


def score(value: float, *, ms: int, ie: str = IE_X, **kw) -> MessageRow:
    return row("trust.score", {"score": value, "id": ie}, ms=ms, **kw)


def so_error(code, *, ms: int, ie: str = IE_X, **kw) -> MessageRow:
    return row("self-orchestrator", {"infrastructureElementId": URN + ie, "errorCode": code},
               ms=ms, **kw)


def llo(event: str, *, ms: int, sc: str = SC_K8S, **kw) -> MessageRow:
    return row("LLO-K8s", {"event": event, "lloId": "llo-k8s-domain1",
                           "serviceComponentId": sc}, ms=ms, **kw)


def security(*, ms: int, ie: str = IE_X, **kw) -> MessageRow:
    return row("self-security", {"infrastructureElementId": URN + ie,
                                 "alert": "ET SCAN Nmap Scripting Engine", "priority": 1},
               ms=ms, **kw)


async def raise_alert(store: Store, a: Alert) -> None:
    """Store an alert and log its event, as the rules engine and the validator do."""
    if await store.put_alert(a):
        await store.emit(events.ALERT, {
            "rule": a.rule, "severity": a.severity,
            "blockId": None if a.block_id is None else to_hex(a.block_id), "ieId": a.ie_id,
            "ts": a.ts, "dedupeKey": a.dedupe_key})


async def store_row(store: Store, r: MessageRow, *, submitted: bool = False,
                    alerts: tuple[str, ...] = ()) -> None:
    if submitted:
        await store.put_submission(Submission(
            sub_id=f"sub-{r.block_id.hex()[:16]}", source="mqtt",
            received_at_ms=r.ts * 1000 - 500, tag=r.tag, block_id=r.block_id,
            hornet_status=201))
    await store.put_message(r)
    for rule in alerts:
        await raise_alert(store, Alert(rule, SEVERITY[rule], r.block_id, r.ie_id,
                                       {"reason": f"test {rule}"}, r.ts * 1000))


async def feed(store: Store, eng: IncidentEngine, r: MessageRow, **kw) -> list[dict]:
    await store_row(store, r, **kw)
    return await eng.on_message(r)


class FakePublisher:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict]] = []
        self.fail = False

    async def publish(self, topic: str, payload: bytes) -> None:
        if self.fail:
            raise ConnectionError("broker refused the connection")
        self.sent.append((topic, json.loads(payload)))


class FakeOrion:
    def __init__(self, hosts: dict, ies: tuple[str, ...] = (IE_X, IE_Y, IE_Z)) -> None:
        self.hosts = hosts
        self.ies = ies
        self.down = False
        self.calls = 0

    async def ie_entities(self, *, max_bytes: int | None = None) -> list[IE]:
        self.calls += 1
        if self.down:
            raise OrionUnavailable("Orion unreachable: refused")
        return [IE(URN + i, i, i.split(":")[0], None) for i in self.ies]

    async def service_component_hosts(self, *, max_bytes: int | None = None) -> dict:
        if self.down:
            raise OrionUnavailable("Orion unreachable: refused")
        return dict(self.hosts)


@pytest.fixture
def pub() -> FakePublisher:
    return FakePublisher()


@pytest.fixture
def engine(store: Store, pub: FakePublisher) -> IncidentEngine:
    return IncidentEngine(store, FakeOrion({SC: IE_X}), IncidentConfig(), pub)


def actions(changes: list[dict]) -> list[str]:
    return [c["action"] for c in changes]


async def incident_events(store: Store) -> list[dict]:
    return [e for e in await store.events_after(0, 1000) if e["type"] == events.INCIDENT]


# -- the aeriOS scenario --------------------------------------------------------------------------

async def test_aerios_incident_is_one_timeline_closed_on_recovery(store, engine, pub):
    # The pipeline calls the engine inside each milestone transaction; the Orion component
    # map is loaded beforehand by the periodic pass, and alerts go out after the commit.
    await engine.periodic(now_ms=(T0 + 300) * 1000)

    async def milestone(r: MessageRow, **kw) -> list[dict]:
        async with store.transaction():
            changes = await feed(store, engine, r, **kw)
        await engine.flush()
        return changes

    assert await milestone(score(0.9, ms=10)) == []  # the pre-incident level
    sec = security(ms=11, verdict=V.UNSIGNED_LEGACY)
    assert actions(await milestone(sec, submitted=True)) == ["opened"]
    drop = score(0.5, ms=12)
    assert actions(await milestone(drop)) == ["attached"]
    err = so_error("isolate-ie", ms=13)
    assert actions(await milestone(err)) == ["attached"]
    failed = llo("Service component failed", ms=14)
    assert actions(await milestone(failed)) == ["attached"]
    assert await milestone(score(0.6, ms=15)) == []  # still below the pre-incident level
    recovered = score(0.92, ms=16)
    assert actions(await milestone(recovered)) == ["attached", "closed"]

    [inc] = await store.incidents()
    assert inc["status"] == "closed:recovered"
    assert inc["ie_id"] == IE_X and inc["severity"] == "high"
    assert inc["closed_by"] == recovered.block_id
    assert IE_X in inc["title"]

    tl = await engine.timeline(inc["id"])
    assert [e["role"] for e in tl["events"]] == [
        "trigger", "trust-drop", "security", "deployment", "remediation"]
    assert [e["blockId"] for e in tl["events"]] == [
        to_hex(r.block_id) for r in (sec, drop, err, failed, recovered)]
    assert tl["incident"]["status"] == "closed:recovered"

    stored = await incident_events(store)
    assert [e["payload"]["action"] for e in stored] == [
        "opened", "attached", "attached", "attached", "attached", "closed"]
    assert [p["action"] for _, p in pub.sent] == [e["payload"]["action"] for e in stored]
    assert {t for t, _ in pub.sent} == {"witness/alerts/high"}
    assert all(p["incidentId"] == inc["id"] for _, p in pub.sent)
    assert pub.sent[-1][1]["status"] == "closed:recovered"


async def test_producer_signed_security_notification_opens(store, engine):
    await feed(store, engine, score(0.9, ms=10))
    note = security(ms=11)  # producer-signed
    [opened] = await feed(store, engine, note)
    assert (opened["action"], opened["role"], opened["severity"]) == ("opened", "trigger", "high")
    [inc] = await store.incidents()
    assert inc["title"] == f"Security notification for {IE_X}"
    assert (inc["baseline_score"], inc["low_score"]) == (0.9, None)  # proven: target known
    [event] = (await engine.timeline(inc["id"]))["events"]
    assert (event["detail"]["as"], event["detail"]["trust"]) == ("security", "proven")
    # a later drop makes it recoverable, back to the level before the notification
    assert actions(await feed(store, engine, score(0.5, ms=12))) == ["attached"]
    assert actions(await feed(store, engine, score(0.91, ms=13))) == ["attached", "closed"]


async def test_unrelated_ie_gets_its_own_incident(store, engine):
    await feed(store, engine, score(0.9, ms=10))
    await feed(store, engine, score(0.9, ms=10, ie=IE_Y))
    assert actions(await feed(store, engine, score(0.4, ms=11))) == ["opened"]
    assert actions(await feed(store, engine, score(0.3, ms=12, ie=IE_Y))) == ["opened"]
    assert actions(await feed(store, engine, so_error("restart", ms=13, ie=IE_Y))) == [
        "attached"]
    by_ie = {i["ie_id"]: i for i in await store.incidents()}
    assert set(by_ie) == {IE_X, IE_Y}
    x = await engine.timeline(by_ie[IE_X]["id"])
    y = await engine.timeline(by_ie[IE_Y]["id"])
    assert [e["role"] for e in x["events"]] == ["trigger"]
    assert [e["role"] for e in y["events"]] == ["trigger", "security"]
    assert by_ie[IE_X]["title"] != by_ie[IE_Y]["title"]


async def test_events_outside_the_window_start_a_new_incident(store, engine):
    await feed(store, engine, score(0.9, ms=10))
    await feed(store, engine, so_error("restart", ms=11))
    # 11 minutes later: past the 10-minute correlation window
    late = so_error("restart", ms=11, ts=T0 + 30 * 11 + 660)
    assert actions(await feed(store, engine, late)) == ["opened"]
    assert len(await store.incidents()) == 2


async def test_small_moves_and_routine_scores_are_not_events(store, engine):
    await feed(store, engine, score(0.9, ms=10))
    assert await feed(store, engine, score(0.75, ms=11)) == []  # 0.15 < 0.2
    assert await feed(store, engine, so_error("0", ms=12)) == []
    assert await feed(store, engine, so_error(0, ms=13)) == []
    assert await feed(store, engine, so_error("", ms=14)) == []
    assert await feed(store, engine, llo("Service component deployed", ms=15)) == []
    assert await store.incidents() == []


# -- what may open, attach and close --------------------------------------------------------------

async def test_forged_and_shadow_blocks_never_close_or_remediate(store, engine):
    await feed(store, engine, score(0.9, ms=10))
    await feed(store, engine, score(0.9, ms=10, ie=IE_Y))
    # Written content alone opens nothing: a drop for Y written around the relay, and a forged
    # report about a component no one can place on an IE (alert only), even once scanned.
    assert await feed(store, engine, score(0.1, ms=11, ie=IE_Y,
                                           verdict=V.UNSIGNED_LEGACY)) == []
    assert await feed(store, engine, llo("Service component failed", ms=11, verdict=V.FORGED,
                                         sc="urn-ngsi-ld-service-ff-component-x"),
                      alerts=("FORGED",)) == []
    await engine.periodic(now_ms=(T0 + 30 * 11) * 1000)
    assert await store.incidents() == []

    assert actions(await feed(store, engine, score(0.4, ms=12))) == ["opened"]
    [inc] = await store.incidents()
    assert inc["severity"] == "high"
    # the forgery joins through its FORGED alert, as evidence of an attack on X
    forged_recovery = score(0.99, ms=13, verdict=V.FORGED)
    [change] = await feed(store, engine, forged_recovery, alerts=("FORGED",))
    assert (change["action"], change["role"], change["severity"]) == (
        "attached", "alert", "critical")
    # untrusted content is not evidence: a signed score already flagged SHADOW, an unsigned
    # one written around the relay
    shadow_recovery = score(0.97, ms=14)
    assert await feed(store, engine, shadow_recovery, alerts=("SHADOW",)) == []
    unsigned_recovery = score(0.98, ms=15, verdict=V.UNSIGNED_LEGACY)
    assert await feed(store, engine, unsigned_recovery) == []
    [inc] = await store.incidents()
    assert inc["status"] == "open" and inc["severity"] == "critical"
    roles = {e["blockId"]: e["role"] for e in (await engine.timeline(inc["id"]))["events"]}
    assert roles[to_hex(forged_recovery.block_id)] == "alert"
    assert to_hex(shadow_recovery.block_id) not in roles
    assert to_hex(unsigned_recovery.block_id) not in roles
    assert "remediation" not in roles.values()

    real = score(0.93, ms=16)
    assert actions(await feed(store, engine, real)) == ["attached", "closed"]
    [inc] = await store.incidents()
    assert inc["status"] == "closed:recovered" and inc["closed_by"] == real.block_id


async def test_attacker_content_never_reshapes_an_incident(store, engine):
    await feed(store, engine, score(0.9, ms=10))
    await feed(store, engine, score(0.4, ms=11))
    [inc] = await store.incidents()
    last = inc["last_event_ms"]
    # an unsigned score written around the relay is no evidence at all
    bypass = score(0.2, ms=12, verdict=V.UNSIGNED_LEGACY, ts=T0 + 330 + 300)
    assert await feed(store, engine, bypass) == []
    [inc] = await store.incidents()
    assert inc["last_event_ms"] == last and inc["low_score"] == 0.4
    # a forged LLO report naming some component of X: its FORGED alert is an attack in
    # progress (the incident stays open), the component claim does not join the keys, and
    # the attack does not move the anchor relayed events are measured from
    forged = llo("Service component failed", ms=13, sc="urn-ngsi-ld-service-ff-component-x",
                 verdict=V.FORGED, ts=T0 + 330 + 500)
    await store_row(store, forged)
    await raise_alert(store, Alert("FORGED", "critical", forged.block_id, IE_X, {}, 1))
    [change] = await engine.on_message(forged)
    assert (change["action"], change["role"], change["severity"]) == (
        "attached", "alert", "critical")
    [inc] = await store.incidents()
    assert inc["last_event_ms"] == (T0 + 830) * 1000 and inc["keys"] == [f"ie:{IE_X}"]
    assert inc["anchor_ms"] == last
    relayed = so_error("restart", ms=14, verdict=V.RELAY_ATTESTED, ts=T0 + 330 + 900)
    assert actions(await feed(store, engine, relayed)) == ["attached"]
    [inc] = await store.incidents()
    # capped at anchor + window (930 s), not its own 1230 s
    assert inc["last_event_ms"] == (T0 + 930) * 1000
    assert await engine.periodic(now_ms=(T0 + 830) * 1000 + 1_800_001) == []
    assert actions(await engine.periodic(now_ms=(T0 + 930) * 1000 + 1_800_001)) == ["closed"]


async def test_a_witnessed_attack_on_an_ie_opens_an_incident(store, engine):
    await feed(store, engine, score(0.9, ms=10, ie=IE_Z))
    forged = score(0.1, ms=11, ie=IE_Z, verdict=V.FORGED)
    [opened] = await feed(store, engine, forged, alerts=("FORGED",))
    assert (opened["action"], opened["role"], opened["rule"]) == ("opened", "trigger", "FORGED")
    [inc] = await store.incidents()
    assert (inc["ie_id"], inc["severity"], inc["status"]) == (IE_Z, "critical", "open")
    assert "Forged" in inc["title"] and IE_Z in inc["title"]
    assert inc["low_score"] is None  # a forged drop is no trust drop
    # the attack goes on: a replay two minutes later joins and keeps the incident open
    replay = score(0.1, ms=15, ie=IE_Z, verdict=V.REPLAY)
    assert actions(await feed(store, engine, replay, alerts=("REPLAY",))) == ["attached"]
    # a forged "recovery" is evidence too, never the closure
    fake_ok = score(0.99, ms=16, ie=IE_Z, verdict=V.FORGED)
    assert actions(await feed(store, engine, fake_ok, alerts=("FORGED",))) == ["attached"]
    [inc] = await store.incidents()
    assert inc["status"] == "open" and inc["last_event_ms"] == (T0 + 30 * 16) * 1000
    tl = await engine.timeline(inc["id"])
    assert [e["role"] for e in tl["events"]] == ["trigger", "alert", "alert"]
    assert [e["verdict"] for e in tl["events"]] == [V.FORGED, V.REPLAY, V.FORGED]
    assert sorted(a["rule"] for a in tl["alerts"]) == ["FORGED", "FORGED", "REPLAY"]
    # only time closes it
    assert actions(await engine.periodic(now_ms=(T0 + 30 * 16) * 1000 + 1_800_001)) == [
        "closed"]


@pytest.mark.parametrize("alert_first", [True, False])
async def test_alerts_on_relayed_blocks_stay_within_a_window(store, engine, alert_first):
    # every few minutes an unsigned error through the relay, each with a faked submission
    # whose bytes differ: a CONTENT_MISMATCH on every one, raised before the block is
    # correlated (same milestone) or found later by the validator (periodic pass)
    await feed(store, engine, score(0.9, ms=10))
    drop = score(0.4, ms=11)
    assert actions(await feed(store, engine, drop)) == ["opened"]
    anchor = drop.ts * 1000
    for n, minutes in enumerate((4, 8, 12, 16, 19), start=1):
        r = so_error("restart", ms=11 + n, verdict=V.UNSIGNED_LEGACY, ts=drop.ts + 60 * minutes)
        mismatch = Alert("CONTENT_MISMATCH", "critical", r.block_id, None,
                         {"reason": "bytes differ"}, r.ts * 1000)
        if alert_first:
            await store_row(store, r, submitted=True)
            await raise_alert(store, mismatch)
            await engine.on_message(r)
        else:
            await feed(store, engine, r, submitted=True)
            await raise_alert(store, mismatch)
            await engine.periodic(now_ms=r.ts * 1000)
        [inc] = await store.incidents()
        assert inc["last_event_ms"] <= anchor + 600_000
    [inc] = await store.incidents()
    assert (inc["last_event_ms"], inc["anchor_ms"]) == (anchor + 600_000, anchor)
    assert await engine.periodic(now_ms=anchor + 600_000 + 1_800_000) == []
    assert actions(await engine.periodic(now_ms=anchor + 600_000 + 1_800_001)) == ["closed"]


@pytest.mark.parametrize("alert_first", [True, False])
async def test_join_only_forgeries_never_keep_an_incident_open(store, engine, alert_first):
    w = "Other:aabbccddeeff"  # an IE Orion does not list: its forgeries can only join
    await feed(store, engine, score(0.9, ms=10, ie=w))
    drop = score(0.4, ms=11, ie=w)
    assert actions(await feed(store, engine, drop)) == ["opened"]
    t0 = drop.ts * 1000
    for n in range(1, 5):
        f = score(0.1, ms=11 + n, ie=w, verdict=V.FORGED, ts=drop.ts + 120 * n)
        forged = Alert("FORGED", "critical", f.block_id, w, {}, f.ts * 1000)
        mismatch = Alert("CONTENT_MISMATCH", "critical", f.block_id, None, {}, f.ts * 1000)
        await store_row(store, f)
        if alert_first:
            await raise_alert(store, forged)
            await raise_alert(store, mismatch)
            await engine.on_message(f)
        else:
            await engine.on_message(f)
            await raise_alert(store, forged)
            await engine.periodic(now_ms=f.ts * 1000)
            await raise_alert(store, mismatch)
            await engine.periodic(now_ms=f.ts * 1000)
        [inc] = await store.incidents()
        assert (inc["last_event_ms"], inc["severity"]) == (t0, "critical")
    [inc] = await store.incidents()
    roles = [e["role"] for e in (await engine.timeline(inc["id"]))["events"]]
    assert roles == ["trigger", "alert", "alert", "alert", "alert"]
    assert actions(await engine.periodic(now_ms=t0 + 1_800_001)) == ["closed"]


async def test_a_sustained_attack_shows_as_bounded_incidents(store, engine):
    # forgeries about a known IE every 4 minutes: each incident stays at most one window
    # past its opening, so the attack shows as a series of incidents that all close
    t = T0 + 330
    for n in range(7):
        f = score(0.1, ms=11 + n, ie=IE_Z, verdict=V.FORGED, ts=t + 240 * n)
        await feed(store, engine, f, alerts=("FORGED",))
    incs = sorted(await store.incidents(), key=lambda i: i["opened_at_ms"])
    assert [i["opened_at_ms"] for i in incs] == [t * 1000, (t + 1440) * 1000]
    assert incs[0]["last_event_ms"] == t * 1000 + 600_000
    assert actions(await engine.periodic(now_ms=t * 1000 + 600_000 + 1_800_001)) == ["closed"]


async def test_attacks_on_ies_orion_does_not_know_stay_alerts(store, engine):
    for n in range(5):
        made_up = score(0.1, ms=10 + n, ie=f"Made:{n:012x}", verdict=V.FORGED)
        assert await feed(store, engine, made_up, alerts=("FORGED",)) == []
    await engine.periodic(now_ms=(T0 + 600) * 1000)
    assert await store.incidents() == []
    assert len(await store.alerts({"rule": "FORGED"})) == 5  # still in /alerts


async def test_without_orion_attack_alerts_only_join(store, pub):
    orion = FakeOrion({})
    orion.down = True
    eng = IncidentEngine(store, orion, IncidentConfig(), pub)
    first = score(0.1, ms=10, ie=IE_Z, verdict=V.FORGED)
    assert await feed(store, eng, first, alerts=("FORGED",)) == []
    assert (await store.service_status())["incident-orion"]["status"] == "unreachable"
    await feed(store, eng, score(0.9, ms=11, ie=IE_Z))
    assert actions(await feed(store, eng, score(0.4, ms=12, ie=IE_Z))) == ["opened"]
    again = score(0.99, ms=13, ie=IE_Z, verdict=V.FORGED)
    assert actions(await feed(store, eng, again, alerts=("FORGED",))) == ["attached"]
    [inc] = await store.incidents()
    assert inc["severity"] == "critical"


async def test_hostile_orion_component_map(store, pub):
    long_sc = "urn:ngsi-ld:Service:0a1b:Component:" + "w" * 500
    hosts = {long_sc: URN + IE_X, "\x00bad\nid\u202e": IE_Y, "": IE_X, "  ": IE_Y,
             "x": "", "y": None, 7: IE_X, "z" * 100_000: "\x1b" + "q" * 5000}
    eng = IncidentEngine(store, FakeOrion(hosts), IncidentConfig(), pub)
    await feed(store, eng, score(0.9, ms=10))
    assert actions(await feed(store, eng, score(0.4, ms=11))) == ["opened"]
    # the component id is cut like the LLO's own report, so the two still line up
    failed = llo("Service component failed", ms=12, sc=long_sc)
    assert actions(await feed(store, eng, failed)) == ["attached"]
    for k, v in eng._hosts.items():
        assert _printable(k) and _printable(v) and len(k) <= 120 and len(v) <= 120
    assert len(eng._hosts) == 3
    # an Orion answering more entities than allowed is not taken at all
    capped = IncidentEngine(store, FakeOrion({SC: IE_X}),
                            IncidentConfig(orion_max_entries=2), pub)
    lone = llo("Service component failed", ms=13, verdict=V.FORGED)
    assert await feed(store, capped, lone, alerts=("FORGED",)) == []
    assert capped._known_ies is None
    st = (await store.service_status())["incident-orion"]
    assert st["status"] == "unreachable" and "more than 2" in st["detail"]


async def test_attack_alerts_find_the_ie_through_the_component(store, engine):
    # the LLO names only its component; Orion places it on X
    rogue = llo("Service component deployed", ms=10, verdict=V.UNAUTHORIZED_WRITER)
    [opened] = await feed(store, engine, rogue, alerts=("UNAUTHORIZED_WRITER",))
    assert (opened["action"], opened["ieId"], opened["severity"]) == ("opened", IE_X, "high")
    # without an IE an attack stays an alert
    lost = llo("Service component failed", ms=11, verdict=V.FORGED,
               sc="urn-ngsi-ld-service-ff-component-q")
    assert await feed(store, engine, lost, alerts=("FORGED",)) == []
    junk = row("unknown-tag", {"anything": 1}, ms=12, verdict=V.FORGED)
    assert await feed(store, engine, junk, alerts=("FORGED",)) == []
    assert [i["ie_id"] for i in await store.incidents()] == [IE_X]


async def test_relay_routed_unsigned_events_may_open(store, engine):
    await feed(store, engine, score(0.9, ms=10, ie=IE_Y))
    drop = score(0.3, ms=11, ie=IE_Y, verdict=V.UNSIGNED_LEGACY)
    assert actions(await feed(store, engine, drop, submitted=True)) == ["opened"]
    # ... but only a PROVEN score closes it
    up = score(0.95, ms=12, ie=IE_Y, verdict=V.UNSIGNED_LEGACY)
    assert await feed(store, engine, up, submitted=True) == []
    [inc] = await store.incidents()
    assert inc["status"] == "open"


async def test_r4_unsigned_score_cannot_open_a_drop(store, engine):
    # unsigned on a tag whose policy requires signatures: the rules raise UNSIGNED, and the
    # relay forwarding it does not make it evidence
    await feed(store, engine, score(0.9, ms=10, ie=IE_Y))
    fake = score(0.1, ms=11, ie=IE_Y, verdict=V.UNSIGNED_LEGACY)
    assert await feed(store, engine, fake, submitted=True, alerts=("UNSIGNED",)) == []
    await engine.periodic(now_ms=(T0 + 400) * 1000)
    assert await store.incidents() == []


async def test_relayed_all_clear_is_no_remediation(store, engine):
    await feed(store, engine, score(0.9, ms=10))
    assert actions(await feed(store, engine, score(0.4, ms=11))) == ["opened"]
    ok = so_error("0", ms=12, verdict=V.UNSIGNED_LEGACY)
    assert await feed(store, engine, ok, submitted=True) == []
    assert actions(await feed(store, engine, so_error("0", ms=13))) == ["attached"]
    [inc] = await store.incidents()
    roles = [e["role"] for e in (await engine.timeline(inc["id"]))["events"]]
    assert roles == ["trigger", "remediation"]


async def test_relay_attested_score_never_closes(store, engine):
    await feed(store, engine, score(0.9, ms=10))
    assert actions(await feed(store, engine, score(0.4, ms=11))) == ["opened"]
    assert await feed(store, engine, score(0.95, ms=12, verdict=V.RELAY_ATTESTED)) == []
    [inc] = await store.incidents()
    assert (inc["status"], inc["low_score"]) == ("open", 0.4)
    assert actions(await feed(store, engine, score(0.95, ms=13))) == ["attached", "closed"]


async def test_recovery_itself_refuses_anything_but_proven(store, engine):
    # white box: whatever hands it a score, the recovery step checks the level itself
    from witness_indexer.incidents import RELAYED, UNTRUSTED, _Obs, _Step

    await feed(store, engine, score(0.9, ms=10))
    assert actions(await feed(store, engine, score(0.4, ms=11))) == ["opened"]
    up = score(0.99, ms=12, verdict=V.RELAY_ATTESTED)
    await store_row(store, up)
    candidates = await store.open_incidents([f"ie:{IE_X}"])
    for level in (RELAYED, UNTRUSTED):
        obs = _Obs(up.block_id, {f"ie:{IE_X}"}, up.ts * 1000, "score", level, ie_id=IE_X,
                   score=0.99)
        step = _Step()
        await engine._recovery(obs, candidates, step)
        assert step.changes == []
    [inc] = await store.incidents()
    assert inc["status"] == "open"


async def test_relayed_triggers_open_and_join_but_never_shape(store, engine):
    await feed(store, engine, score(0.9, ms=10, ie=IE_Y))
    drop = score(0.3, ms=11, ie=IE_Y, verdict=V.RELAY_ATTESTED)
    assert actions(await feed(store, engine, drop)) == ["opened"]
    [inc] = await store.incidents()
    assert (inc["baseline_score"], inc["low_score"], inc["keys"]) == (None, None, [f"ie:{IE_Y}"])
    # a relayed LLO failure on a component Orion places on X joins X's incident without
    # adding its component to the keys
    await feed(store, engine, score(0.9, ms=10))
    assert actions(await feed(store, engine, score(0.4, ms=11))) == ["opened"]
    failed = llo("Service component failed", ms=12, verdict=V.RELAY_ATTESTED)
    assert actions(await feed(store, engine, failed)) == ["attached"]
    x = next(i for i in await store.incidents() if i["ie_id"] == IE_X)
    assert x["keys"] == [f"ie:{IE_X}"]


TM = "did:iota:testnet:0x" + "15" * 32
POLICY = writer_policy.load({
    "version": 1,
    "tags": {"trust.score": {"allowed": [TM], "require_signature": True,
                             "legacy_grace": False}},
    "default": {"allowed": ["*"], "require_signature": False, "legacy_grace": True},
})


async def test_policy_decides_trust_without_waiting_for_the_rules(store, pub):
    eng = IncidentEngine(store, FakeOrion({SC: IE_X}), IncidentConfig(), pub, policy=POLICY)
    await feed(store, eng, dataclasses.replace(score(0.9, ms=10), iss=TM))
    # unsigned on a tag that requires signatures, sent through the relay, and the rules
    # have not (or could not) raise UNSIGNED: still not evidence
    unsigned = score(0.1, ms=11, verdict=V.UNSIGNED_LEGACY)
    assert await feed(store, eng, unsigned, submitted=True) == []
    # a producer-signed verdict from a writer the policy does not list (a stale verdict)
    outsider = dataclasses.replace(score(0.1, ms=12), iss="did:iota:testnet:0xbad")
    assert await feed(store, eng, outsider) == []
    # verdicts the engine does not know count for nothing
    for n, verdict in enumerate((None, "SOMETHING_NEW")):
        assert await feed(store, eng, score(0.1, ms=13 + n, verdict=verdict)) == []
    assert await store.incidents() == []
    # the listed writer's drop is proven
    drop = dataclasses.replace(score(0.2, ms=15), iss=TM)
    assert actions(await feed(store, eng, drop)) == ["opened"]
    [inc] = await store.incidents()
    assert (inc["baseline_score"], inc["low_score"]) == (0.9, 0.2)


async def test_integrity_alerts_and_relayed_context_shape_nothing(store, engine):
    await feed(store, engine, score(0.9, ms=10))
    drop = score(0.4, ms=11)
    assert actions(await feed(store, engine, drop)) == ["opened"]
    [inc] = await store.incidents()
    anchor, keys = inc["anchor_ms"], inc["keys"]
    # relayed context (an LLO "deployed" on a component of X) is not a trigger: it stays out
    deployed = llo("Service component deployed", ms=12, verdict=V.RELAY_ATTESTED)
    assert await feed(store, engine, deployed) == []
    # an integrity alert naming X joins, keeps the incident going, shapes nothing
    other = so_error("restart", ms=13, verdict=V.UNSIGNED_LEGACY)
    await store_row(store, other, submitted=True)
    await raise_alert(store, Alert("CONTENT_MISMATCH", "critical", other.block_id, IE_X,
                                {"reason": "bytes differ"}, other.ts * 1000))
    assert actions(await engine.periodic(now_ms=other.ts * 1000)) == ["attached"]
    [inc] = await store.incidents()
    assert (inc["anchor_ms"], inc["keys"], inc["severity"]) == (anchor, keys, "critical")
    assert inc["last_event_ms"] == other.ts * 1000 - 500


async def test_relayed_traffic_cannot_keep_an_incident_open(store, engine):
    opened_s = T0 + 330
    first = so_error("restart", ms=11, verdict=V.RELAY_ATTESTED)
    assert actions(await feed(store, engine, first)) == ["opened"]
    for i, delay in enumerate((480, 960, 1150)):  # each within a window of the last one
        r = so_error("restart", ms=12 + i, verdict=V.RELAY_ATTESTED, ts=opened_s + delay)
        assert actions(await feed(store, engine, r)) == ["attached"]
    [inc] = await store.incidents()
    assert inc["last_event_ms"] == opened_s * 1000 + 600_000  # one window past the opening
    assert actions(await engine.periodic(now_ms=opened_s * 1000 + 600_000 + 1_800_001)) == [
        "closed"]


async def test_self_orchestrator_error_alone_closes_only_when_quiet(store, engine):
    await feed(store, engine, score(0.9, ms=10))
    assert actions(await feed(store, engine, so_error(503, ms=11))) == ["opened"]
    # a routine score at the pre-incident level is no recovery: nothing dropped
    assert await feed(store, engine, score(0.9, ms=12)) == []
    [inc] = await store.incidents()
    last = inc["last_event_ms"]
    assert await engine.periodic(now_ms=last + 1_800_000) == []
    assert actions(await engine.periodic(now_ms=last + 1_800_001)) == ["closed"]
    [inc] = await store.incidents()
    assert inc["status"] == "closed:quiet" and inc["closed_at_ms"] == last + 1_800_001
    assert await engine.periodic(now_ms=last + 9_000_000) == []
    # the next error starts a new incident
    assert actions(await feed(store, engine, so_error(503, ms=200))) == ["opened"]


async def test_event_time_comes_from_the_ledger(store, engine):
    await feed(store, engine, score(0.9, ms=10))
    drop = score(0.4, ms=11)
    # the submission record claims the relay received the block in 2100
    await store.put_submission(Submission(
        sub_id="sub-future", source="mqtt", received_at_ms=4_102_444_800_000,
        tag="trust.score", block_id=drop.block_id, hornet_status=201))
    assert actions(await feed(store, engine, drop)) == ["opened"]
    [inc] = await store.incidents()
    assert inc["opened_at_ms"] == inc["last_event_ms"] == drop.ts * 1000
    # a receipt shortly before the milestone is believed
    err = so_error("restart", ms=12)
    await store_row(store, err, submitted=True)  # received 500 ms before its milestone
    assert actions(await engine.on_message(err)) == ["attached"]
    [inc] = await store.incidents()
    assert inc["last_event_ms"] == err.ts * 1000 - 500
    assert actions(await engine.periodic(now_ms=err.ts * 1000 - 500 + 1_800_001)) == [
        "closed"]


async def test_quiet_close_runs_on_the_ledger_clock(store, engine):
    await feed(store, engine, score(0.9, ms=10))
    drop = score(0.4, ms=11)
    assert actions(await feed(store, engine, drop)) == ["opened"]
    await store.put_milestone(11, b"\x01" * 32, drop.ts, b"", [], b"\x00" * 32, b"\x00" * 32)
    # a backfill: the wall clock is days ahead, the ledger is still at the incident
    far = drop.ts * 1000 + 10 * 86_400_000
    assert await engine.periodic(now_ms=far) == []
    await store.put_milestone(12, b"\x02" * 32, drop.ts + 1801, b"", [], b"\x00" * 32,
                              b"\x01" * 32)
    assert actions(await engine.periodic(now_ms=far)) == ["closed"]


async def test_shadow_found_later_takes_back_what_the_block_did(store, engine):
    await feed(store, engine, score(0.9, ms=10))
    drop = score(0.4, ms=11)
    assert actions(await feed(store, engine, drop)) == ["opened"]
    recovered = score(0.95, ms=12)
    assert actions(await feed(store, engine, recovered)) == ["attached", "closed"]
    # R14 runs 30 s after confirmation: the recovery was written around the relay
    await raise_alert(store, Alert("SHADOW", "high", recovered.block_id, IE_X,
                                   {"reason": "never received"}, recovered.ts * 1000 + 31_000))
    changes = await engine.periodic(now_ms=recovered.ts * 1000 + 31_000)
    assert [(c["action"], c.get("role")) for c in changes] == [
        ("revoked", "remediation"), ("reopened", None)]
    [inc] = await store.incidents()
    assert (inc["status"], inc["closed_by"], inc["closed_at_ms"]) == ("open", None, None)
    assert (inc["baseline_score"], inc["low_score"]) == (0.9, 0.4)
    events_ = {e["blockId"]: e for e in (await engine.timeline(inc["id"]))["events"]}
    rec = events_[to_hex(recovered.block_id)]
    assert rec["role"] == "alert"
    assert (rec["detail"]["revoked"], rec["detail"]["was"]) == ("shadow", "remediation")
    # the drop behind the recovery target was a bypass write too: no genuine drop is left
    await raise_alert(store, Alert("SHADOW", "high", drop.block_id, IE_X, {},
                                   drop.ts * 1000 + 31_000))
    assert actions(await engine.periodic(now_ms=recovered.ts * 1000 + 40_000)) == ["revoked"]
    [inc] = await store.incidents()
    assert inc["low_score"] is None
    # so a proven score at the old level closes nothing; only time does
    assert await feed(store, engine, score(0.96, ms=13)) == []
    [inc] = await store.incidents()
    assert inc["status"] == "open"


async def test_recovery_target_is_the_level_the_first_drop_fell_from(store, engine):
    await feed(store, engine, score(0.9, ms=10))
    assert actions(await feed(store, engine, so_error("restart", ms=11))) == ["opened"]
    assert await feed(store, engine, score(0.95, ms=12)) == []
    assert actions(await feed(store, engine, score(0.6, ms=13))) == ["attached"]
    assert await feed(store, engine, score(0.92, ms=14)) == []  # above 0.9, below 0.95
    assert await feed(store, engine, score(0.78, ms=15)) == []
    assert await feed(store, engine, score(0.59, ms=16)) == []  # lower, but not a new drop
    [inc] = await store.incidents()
    assert (inc["status"], inc["baseline_score"], inc["low_score"]) == ("open", 0.95, 0.59)
    assert actions(await feed(store, engine, score(0.96, ms=17))) == ["attached", "closed"]


async def test_llo_failure_correlates_by_component_without_orion(store, pub):
    orion = FakeOrion({})
    orion.down = True
    eng = IncidentEngine(store, orion, IncidentConfig(), pub)
    assert actions(await feed(store, eng, llo("Service component failed", ms=10))) == [
        "opened"]
    other = llo("Service component failed", ms=10, sc="urn-ngsi-ld-service-0a1b-component-db")
    assert actions(await feed(store, eng, other)) == ["opened"]
    assert actions(await feed(store, eng, llo("Service component deployed", ms=11))) == [
        "attached"]
    # the IE's drop is not linked to the component: Orion never said where it runs
    await feed(store, eng, score(0.9, ms=11))
    assert actions(await feed(store, eng, score(0.2, ms=12))) == ["opened"]
    incs = await store.incidents()
    assert len(incs) == 3
    web = next(i for i in incs if "web" in i["title"])
    tl = await eng.timeline(web["id"])
    assert [e["role"] for e in tl["events"]] == ["trigger", "deployment"]


async def test_llo_failure_joins_the_ie_incident_through_orion(store, engine):
    await feed(store, engine, score(0.9, ms=10))
    await feed(store, engine, score(0.4, ms=11))
    assert actions(await feed(store, engine, llo("Service component failed", ms=12))) == [
        "attached"]
    # once joined, the component's later events follow the incident
    assert actions(await feed(store, engine, llo("Service component deployed", ms=13))) == [
        "attached"]
    [inc] = await store.incidents()
    roles = [e["role"] for e in (await engine.timeline(inc["id"]))["events"]]
    assert roles == ["trigger", "deployment", "deployment"]


def test_component_key_lines_up_llo_names_and_orion_ids():
    assert component_key(SC_K8S) == component_key(SC)
    assert component_key("URN-NGSI-LD-SERVICE-0A1B-COMPONENT-web") == component_key(SC)
    assert component_key("plain-name") == "plain-name"


# -- alerts as triggers ---------------------------------------------------------------------------

async def test_integrity_alerts_group_into_a_ledger_incident(store, engine):
    a = llo("Service component deployed", ms=10, verdict=V.UNSIGNED_LEGACY)
    b = llo("Service component updated", ms=11, verdict=V.UNSIGNED_LEGACY)
    await store_row(store, a, submitted=True)
    await store_row(store, b, submitted=True)
    for bid, rule in ((a.block_id, "CONTENT_MISMATCH"), (b.block_id, "DB_TAMPER")):
        await raise_alert(store, Alert(rule, "critical", bid, None, {"reason": rule}, T0 * 1000))
    await raise_alert(store, Alert("ANCHOR_MISMATCH", "critical", None, None,
                                {"reason": "root differs", "seq": 4}, T0 * 1000))
    await raise_alert(store, Alert("STALE", "low", None, IE_X, {}, T0 * 1000))
    changes = await engine.periodic(now_ms=(T0 + 330) * 1000)
    assert actions(changes) == ["opened", "attached", "updated"]
    [inc] = await store.incidents()
    assert inc["ie_id"] is None and inc["severity"] == "critical"
    tl = await engine.timeline(inc["id"])
    assert [e["role"] for e in tl["events"]] == ["trigger", "alert"]
    assert sorted(x["rule"] for x in tl["alerts"]) == [
        "ANCHOR_MISMATCH", "CONTENT_MISMATCH", "DB_TAMPER"]
    assert await engine.periodic(now_ms=(T0 + 340) * 1000) == []  # idempotent


async def test_no_alert_is_skipped_when_transactions_commit_out_of_order(store, engine):
    # an alert stored early in a long transaction gets a lower id than alerts that commit
    # before it; its event is logged (and so read) only when its transaction commits
    late = llo("Service component updated", ms=10, verdict=V.UNSIGNED_LEGACY)
    await store_row(store, late, submitted=True)
    late_alert = Alert("CONTENT_MISMATCH", "critical", late.block_id, None, {}, T0 * 1000)
    assert await store.put_alert(late_alert)  # id 1, event not logged yet
    for n in range(60):
        await raise_alert(store, Alert("ANCHOR_MISMATCH", "critical", None, None, {},
                                       T0 * 1000, dedupe_key=f"seq:{n}"))
    assert actions(await engine.periodic(now_ms=(T0 + 300) * 1000))[0] == "opened"
    [a_late] = await store.alerts({"rule": "CONTENT_MISMATCH"})
    assert not await store.incident_alert_linked(a_late["id"])
    await store.emit(events.ALERT, {"rule": "CONTENT_MISMATCH", "severity": "critical",
                                    "blockId": to_hex(late.block_id), "ieId": None,
                                    "ts": T0 * 1000, "dedupeKey": None})
    assert actions(await engine.periodic(now_ms=(T0 + 301) * 1000)) == ["attached"]
    assert await store.incident_alert_linked(a_late["id"])


async def test_alert_on_a_proven_block_opens_and_alerts_raise_severity(store, engine):
    fork = so_error("0", ms=10)
    changes = await feed(store, engine, fork, alerts=("CHAIN_FORK",))
    assert actions(changes) == ["opened"]
    [inc] = await store.incidents()
    assert inc["ie_id"] == IE_X and inc["severity"] == "high"
    assert "CHAIN_FORK" in inc["title"] or "fork" in inc["title"].lower()
    # an alert raised later (validator) on a block already in the incident raises its severity
    await raise_alert(store, Alert("CONTENT_MISMATCH", "critical", fork.block_id, None, {},
                                T0 * 1000))
    assert actions(await engine.periodic(now_ms=(T0 + 400) * 1000)) == ["updated"]
    [inc] = await store.incidents()
    assert inc["severity"] == "critical"


# -- delivery ------------------------------------------------------------------------------------

async def test_publisher_failure_never_breaks_indexing(store, engine, pub):
    pub.fail = True
    await feed(store, engine, score(0.9, ms=10))
    assert actions(await feed(store, engine, score(0.3, ms=11))) == ["opened"]
    assert await engine.flush() == 0
    assert (await store.service_status())["alerts-mqtt"]["status"] == "unreachable"
    assert pub.sent == []
    pub.fail = False
    assert await engine.flush() == 1  # the backlog goes out once the broker is back
    assert [p["action"] for _, p in pub.sent] == ["opened"]
    assert (await store.service_status())["alerts-mqtt"]["status"] == "ok"
    assert await engine.flush() == 0


async def test_nothing_is_published_before_commit(store, engine, pub):
    await feed(store, engine, score(0.9, ms=10))
    with pytest.raises(RuntimeError):
        async with store.transaction():
            await feed(store, engine, score(0.3, ms=11))
            assert await engine.flush() == 0
            raise RuntimeError("milestone failed")
    assert await engine.flush() == 0 and pub.sent == []
    assert await store.incidents() == []
    async with store.transaction():
        await feed(store, engine, score(0.3, ms=12))
        assert pub.sent == []
    assert await engine.flush() == 1
    [(topic, payload)] = pub.sent
    assert topic == "witness/alerts/high" and payload["action"] == "opened"
    assert payload["eventId"] > 0 and payload["blockId"].startswith("0x")


async def test_publisher_cursor_survives_a_restart(store, pub):
    eng = IncidentEngine(store, None, IncidentConfig(), pub)
    await feed(store, eng, score(0.9, ms=10))
    await feed(store, eng, score(0.3, ms=11))
    assert await eng.flush() == 1
    again = IncidentEngine(store, None, IncidentConfig(), pub)
    assert await again.flush() == 0
    await feed(store, again, so_error("restart", ms=12))
    assert await again.flush() == 1
    assert [p["action"] for _, p in pub.sent] == ["opened", "attached"]


async def until(cond, timeout_s: float = 3.0) -> None:
    async def poll() -> None:
        while not cond():
            await asyncio.sleep(0.02)

    await asyncio.wait_for(poll(), timeout_s)


async def test_only_the_publisher_task_talks_to_the_broker(store, pub):
    eng = IncidentEngine(store, None, IncidentConfig(publish_poll_s=60), pub)
    await feed(store, eng, score(0.9, ms=10))
    assert actions(await feed(store, eng, score(0.3, ms=11))) == ["opened"]
    await eng.periodic(now_ms=(T0 + 400) * 1000)
    assert pub.sent == []  # neither the message path nor the periodic pass published
    task = asyncio.create_task(eng.run_publisher())
    try:
        await until(lambda: len(pub.sent) == 1)
        # it would sleep for a minute; a new change wakes it at once
        assert actions(await feed(store, eng, so_error("restart", ms=12))) == ["attached"]
        await until(lambda: len(pub.sent) == 2)
    finally:
        await eng.stop_publisher()
        await asyncio.wait_for(task, 5)


# -- timeline -------------------------------------------------------------------------------------

async def test_timeline_reports_verdict_and_lifecycle_per_event(store, engine):
    await feed(store, engine, score(0.9, ms=10))
    drop = score(0.4, ms=11, verdict=V.RELAY_ATTESTED)
    await feed(store, engine, drop, submitted=True)
    await store.set_lifecycle(block_id=drop.block_id, sub_id=None, status="CONFIRMED",
                              at_ms=(T0 + 331) * 1000)
    await store.set_lifecycle(block_id=drop.block_id, sub_id=None, status="CONTENT_VERIFIED",
                              at_ms=(T0 + 332) * 1000)
    forged = score(0.99, ms=12, verdict=V.FORGED)
    await feed(store, engine, forged, alerts=("FORGED",))
    err = so_error("isolate-ie", ms=13)
    await feed(store, engine, err)
    [inc] = await store.incidents()
    tl = await engine.timeline(inc["id"])
    assert tl["incident"]["id"] == inc["id"] and tl["incident"]["ieId"] == IE_X
    got = [(e["blockId"], e["verdict"], e["status"], e["role"]) for e in tl["events"]]
    assert got == [
        (to_hex(drop.block_id), V.RELAY_ATTESTED, "CONTENT_VERIFIED", "trigger"),
        (to_hex(forged.block_id), V.FORGED, "CONFIRMED", "alert"),
        (to_hex(err.block_id), V.PRODUCER_SIGNED, "CONFIRMED", "security"),
    ]
    times = [e["atMs"] for e in tl["events"]]
    assert times == sorted(times)
    assert all(e["proof"] == f"/proofs/{e['blockId']}" for e in tl["events"])
    assert [a["rule"] for a in tl["alerts"]] == ["FORGED"]
    assert await engine.timeline(10**9) is None


# -- robustness -----------------------------------------------------------------------------------

def _printable(s: str) -> bool:
    return all(unicodedata.category(ch)[0] != "C" for ch in s)


async def test_hostile_strings_are_sanitised(store, engine, pub):
    async def hostile(r: MessageRow) -> list[dict]:
        # PostgreSQL refuses NUL and lone surrogates in jsonb: the row is stored without its
        # parsed body, the engine still sees the body the pipeline decoded.
        await store_row(store, dataclasses.replace(r, json=None))
        return await engine.on_message(r)

    nasty = "\x1b[31mDROP TABLE incidents;\x00\ud800\u202e" + "A" * 5000 + "\n\r\t"
    await feed(store, engine, score(0.9, ms=10, ie=IE_Y))
    assert actions(await hostile(so_error(nasty, ms=11, ie=IE_Y))) == ["opened"]
    bad_sc = "x\n" * 300 + "\x00\u202e"
    assert actions(await hostile(llo("Service component failed", ms=12, sc=bad_sc))) == [
        "opened"]
    incs = await store.incidents()
    for inc in incs:
        assert _printable(inc["title"]) and len(inc["title"]) <= 200
        assert all(_printable(k) and len(k) <= 200 for k in inc["keys"])
    assert await engine.flush() == 2
    for _, payload in pub.sent:
        assert _printable(payload["title"])
    tl = await engine.timeline(incs[-1]["id"])
    json.dumps(tl)


async def test_a_failure_is_isolated_in_the_callers_transaction(store, engine, monkeypatch):
    await feed(store, engine, score(0.9, ms=10))

    async def broken(*a, **k):
        raise RuntimeError("incident bug")

    monkeypatch.setattr(store, "put_incident", broken)
    drop = score(0.3, ms=11)
    async with store.transaction():
        await store_row(store, drop)
        assert await engine.on_message(drop) == []
        await store.put_ie_score(IE_X, 11, drop.ts, 0.3, drop.block_id, drop.verdict)
    assert await store.get_message(drop.block_id) is not None  # the milestone committed
    st = (await store.service_status())["incident-engine"]
    assert st["status"] == "error" and "incident bug" in st["detail"]
    assert await store.incidents() == []
    monkeypatch.undo()
    # the next message works again
    assert actions(await feed(store, engine, score(0.05, ms=12))) == ["opened"]


async def test_reprocessing_a_message_changes_nothing(store, engine):
    await feed(store, engine, score(0.9, ms=10))
    drop = score(0.4, ms=11)
    assert actions(await feed(store, engine, drop)) == ["opened"]
    assert await engine.on_message(drop) == []
    [inc] = await store.incidents()
    await engine.periodic(now_ms=inc["last_event_ms"] + 1_800_001)
    assert await engine.on_message(drop) == []  # closed now: still not a second incident
    assert len(await store.incidents()) == 1


async def test_message_without_a_stored_row_or_ie_is_ignored(store, engine):
    r = row("trust.score", {"score": "high", "id": "nope"}, ms=10)
    assert await engine.on_message(r) == []
    r = row("unknown-tag", {"anything": 1}, ms=10)
    assert await feed(store, engine, r) == []
    assert await store.incidents() == []


async def test_correlated_rules_feeds_both_engines(store, engine):
    class Rules:
        anchor = "anchor-client"

        def __init__(self) -> None:
            self.seen: list[bytes] = []
            self.periodic_calls = 0

        async def on_message(self, r: MessageRow) -> list[Alert]:
            self.seen.append(r.block_id)
            return [Alert("ANOMALY", "medium", r.block_id, r.ie_id, {}, 1)]

        async def periodic(self, *, now_ms: int) -> list[Alert]:
            self.periodic_calls += 1
            return []

    rules = Rules()
    hook = CorrelatedRules(rules, engine)
    await store_row(store, score(0.9, ms=10))
    drop = score(0.3, ms=11)
    await store_row(store, drop)
    [alert] = await hook.on_message(drop)
    assert alert.rule == "ANOMALY" and rules.seen == [drop.block_id]
    assert len(await store.incidents()) == 1
    assert await hook.periodic(now_ms=(T0 + 400) * 1000) == []
    assert rules.periodic_calls == 1
    assert hook.anchor == "anchor-client"


# -- the aiomqtt publisher ------------------------------------------------------------------------

def test_mqtt_publisher_rejects_other_schemes():
    with pytest.raises(ValueError):
        MqttAlertPublisher("http://127.0.0.1:1883")


async def test_unreachable_broker_is_reported_not_raised(store):
    pub = MqttAlertPublisher("mqtt://127.0.0.1:1", timeout_s=2.0)
    with pytest.raises(Exception):  # noqa: B017 - whatever the transport raises
        await pub.publish("witness/alerts/high", b"{}")
    eng = IncidentEngine(store, None, IncidentConfig(), pub)
    await feed(store, eng, score(0.9, ms=10))
    assert actions(await feed(store, eng, score(0.3, ms=11))) == ["opened"]
    assert await eng.flush() == 0
    assert (await store.service_status())["alerts-mqtt"]["status"] == "unreachable"
    await eng.aclose()


LIVE_MQTT = os.environ.get("WITNESS_LIVE_MQTT", "mqtt://127.0.0.1:1883")


@pytest.mark.live
@pytest.mark.skipif(os.environ.get("WITNESS_LIVE") != "1", reason="set WITNESS_LIVE=1")
async def test_alerts_reach_mosquitto(store):
    import aiomqtt

    parts = urlsplit(LIVE_MQTT)
    async with aiomqtt.Client(parts.hostname, parts.port or 1883,
                              identifier=f"witness-test-{uuid.uuid4().hex[:8]}") as sub:
        prefix = f"witness-test/{uuid.uuid4().hex[:8]}/alerts"
        await sub.subscribe(f"{prefix}/#", qos=1)
        pub = MqttAlertPublisher(LIVE_MQTT, client_id=f"witness-test-pub-{uuid.uuid4().hex[:8]}")
        eng = IncidentEngine(store, None, IncidentConfig(mqtt_topic_prefix=prefix), pub)
        await feed(store, eng, score(0.9, ms=10))
        await feed(store, eng, score(0.3, ms=11))
        assert await eng.flush() == 1
        msg = await asyncio.wait_for(anext(aiter(sub.messages)), 10)
        await eng.aclose()
    assert str(msg.topic) == f"{prefix}/high" and msg.qos == 1
    body = json.loads(msg.payload)
    assert body["action"] == "opened" and body["ieId"] == IE_X
