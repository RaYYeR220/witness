"""GET /incidents and /incidents/{id} on incidents the indexer's correlation engine built."""

import itertools
import json

from witness_core import schema
from witness_core import verdicts as V
from witness_core.ids import blake2b256, to_hex
from witness_indexer import events
from witness_indexer.incidents import IncidentConfig, IncidentEngine
from witness_indexer.store import Alert, MessageRow, Submission

IE = "MyDomain:fa163e5e25ef"
T0 = 1_791_280_000  # seconds
_blocks = itertools.count(1)


def score(value: float, *, ms: int, verdict: str = V.PRODUCER_SIGNED) -> MessageRow:
    data = json.dumps({"score": value, "id": IE}).encode()
    c = schema.classify("trust.score", data)
    return MessageRow(
        block_id=blake2b256(data + next(_blocks).to_bytes(8, "big")), tag="trust.score",
        kind=c.kind, data=data, json=c.json, ie_id=c.ie_id, verdict=verdict, ms_index=ms,
        wf_index=0, ts=T0 + 30 * ms)


async def raise_alert(store, a: Alert) -> None:
    """Store an alert and log its event, as the rules engine and the validator do."""
    if await store.put_alert(a):
        await store.emit(events.ALERT, {
            "rule": a.rule, "severity": a.severity,
            "blockId": None if a.block_id is None else to_hex(a.block_id), "ieId": a.ie_id,
            "ts": a.ts, "dedupeKey": a.dedupe_key})


def hx(b: bytes) -> str:
    return "0x" + b.hex()


async def test_engine_incident_through_the_api(client, store):
    engine = IncidentEngine(store, None, IncidentConfig())
    base, drop = score(0.9, ms=10), score(0.4, ms=11)
    forged, recovered = score(0.99, ms=12, verdict=V.FORGED), score(0.95, ms=13)
    await store.put_submission(Submission(
        sub_id="sub-drop", source="mqtt", received_at_ms=drop.ts * 1000 - 500,
        tag="trust.score", block_id=drop.block_id, hornet_status=201))
    for r in (base, drop, forged, recovered):
        await store.put_message(r)
        if r is forged:
            await raise_alert(store, Alert("FORGED", "critical", r.block_id, IE,
                                        {"reason": "signature does not verify"}, r.ts * 1000))
        if r is drop:
            await store.set_lifecycle(block_id=r.block_id, sub_id="sub-drop",
                                      status="CONTENT_VERIFIED", at_ms=r.ts * 1000 + 900)
        await engine.on_message(r)

    r = await client.get("/incidents", params={"status": "closed:recovered"})
    assert r.status_code == 200, r.text
    [inc] = r.json()["items"]
    assert (inc["ieId"], inc["severity"], inc["keys"]) == (IE, "critical", [f"ie:{IE}"])
    assert (inc["baselineScore"], inc["lowScore"]) == (0.9, 0.4)
    assert inc["closedBy"] == hx(recovered.block_id)
    assert inc["lastEventMs"] == recovered.ts * 1000 and inc["lastEventAt"].endswith("Z")
    assert "dropped 0.90 -> 0.40" in inc["title"]

    r = await client.get(f"/incidents/{inc['id']}")
    assert r.status_code == 200, r.text
    detail = r.json()
    events = detail["events"]
    assert [(e["blockId"], e["role"], e["verdict"], e["status"]) for e in events] == [
        (hx(drop.block_id), "trigger", V.PRODUCER_SIGNED, "CONTENT_VERIFIED"),
        (hx(forged.block_id), "alert", V.FORGED, "CONFIRMED"),
        (hx(recovered.block_id), "remediation", V.PRODUCER_SIGNED, "CONFIRMED"),
    ]
    assert [e["atMs"] for e in events] == [drop.ts * 1000 - 500, forged.ts * 1000,
                                           recovered.ts * 1000]
    assert events[0]["detail"]["as"] == "trust-drop" and events[0]["indexed"] is True
    assert all(e["links"]["proof"] == f"/proofs/{e['blockId']}" for e in events)
    [alert] = detail["alerts"]
    assert (alert["rule"], alert["blockId"], alert["ieId"]) == (
        "FORGED", hx(forged.block_id), IE)
    assert alert["evidence"] == {"reason": "signature does not verify"}


async def test_ledger_incident_without_an_indexed_message(client, store):
    # ORPHANED: the relay submitted a block the Tangle never confirmed; no message row exists
    engine = IncidentEngine(store, None, IncidentConfig())
    bid = blake2b256(b"never confirmed")
    await store.put_submission(Submission(sub_id="sub-o", source="http",
                                          received_at_ms=T0 * 1000, tag="trust.score",
                                          block_id=bid, hornet_status=201))
    await store.set_lifecycle(block_id=bid, sub_id="sub-o", status="ORPHANED",
                              at_ms=T0 * 1000 + 60_000)
    await raise_alert(store, Alert("ORPHANED", "high", bid, None, {"reason": "never confirmed"},
                                T0 * 1000 + 60_000))
    await engine.periodic(now_ms=T0 * 1000 + 61_000)
    [inc] = (await client.get("/incidents")).json()["items"]
    assert inc["ieId"] is None and inc["keys"] == ["ledger"] and inc["status"] == "open"
    detail = (await client.get(f"/incidents/{inc['id']}")).json()
    [event] = detail["events"]
    assert (event["blockId"], event["role"], event["status"], event["indexed"]) == (
        hx(bid), "trigger", "ORPHANED", False)
    assert event["verdict"] is None and event["tag"] is None
    assert [a["rule"] for a in detail["alerts"]] == ["ORPHANED"]


async def test_incident_detail_is_paged(client, store):
    iid = await store.put_incident(opened_at_ms=T0 * 1000, severity="high", title="big",
                                   ie_id=IE, keys=[f"ie:{IE}"])
    blocks = [blake2b256(b"event %d" % n) for n in range(5)]
    for n, bid in enumerate(blocks):
        await store.attach_incident_event(iid, bid, "trigger" if n == 0 else "alert",
                                          at_ms=T0 * 1000 + n)
    for n in range(3):
        await raise_alert(store, Alert("ANCHOR_MISMATCH", "critical", None, None, {}, T0 * 1000,
                                       dedupe_key=f"seq:{n}"))
    for a in await store.alerts({"rule": "ANCHOR_MISMATCH"}):
        await store.link_incident_alert(a["id"], iid, T0 * 1000)

    seen, alerts, params = [], [], {"limit": 2}
    while True:
        r = await client.get(f"/incidents/{iid}", params=params)
        assert r.status_code == 200, r.text
        page = r.json()
        assert (page["eventsTotal"], page["alertsTotal"]) == (5, 3)
        assert len(page["events"]) <= 2 and len(page["alerts"]) <= 2
        seen += [e["blockId"] for e in page["events"]]
        alerts += [a["id"] for a in page["alerts"]]
        if page["nextEventsCursor"] is None and page["nextAlertsAfter"] is None:
            break
        params = {"limit": 2}
        if page["nextEventsCursor"]:
            params["eventsAfter"] = page["nextEventsCursor"]
        if page["nextAlertsAfter"]:
            params["alertsAfter"] = page["nextAlertsAfter"]
        else:
            params["alertsAfter"] = max(alerts)
    assert seen[:5] == [hx(b) for b in blocks] and len(set(seen)) == 5
    assert len(alerts) == len(set(alerts)) == 3
    for bad in ("x", "12:zz", "1:" + "ab" * 31):
        r = await client.get(f"/incidents/{iid}", params={"eventsAfter": bad})
        assert r.status_code == 422
    assert (await client.get(f"/incidents/{iid}", params={"limit": 501})).status_code == 422
