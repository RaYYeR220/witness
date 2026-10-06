import json
from dataclasses import replace

import httpx
import respx
from apiseed import ISS, put_signed, sealed_score, seed_chain
from conftest import ANCHOR, ORION
from witness_api.app import create_app
from witness_core import canon, checkpoint, verdicts
from witness_core.ids import from_hex
from witness_core.sealed import blind_token
from witness_indexer.store import Alert, MessageRow

B370_4 = "0x972a878cf06f2cf6b7d4a1443dbb5f12fdda376fa7537a82dad8e7257a477967"
B370_5 = "0x0b947e1c252402a7ff24faf9aeb54cfdcdc65c9c10ff6fd9bf89b4dbcca98adc"
IE = "MyDomain:fa163e5e25ef"
MS371_TS = 1791283579  # 2026-10-06T10:46:19Z
ORION_ENTITY = f"{ORION}/ngsi-ld/v1/entities/urn:ngsi-ld:InfrastructureElement:{IE}"


async def page_all(client, **params):
    out, cursor = [], None
    while True:
        q = dict(params, **({"cursor": cursor} if cursor else {}))
        r = await client.get("/messages", params=q)
        assert r.status_code == 200, r.text
        body = r.json()
        out += body["items"]
        cursor = body["nextCursor"]
        if not cursor:
            return out


def ids(items):
    return [m["blockId"] for m in items]


# -- search -----------------------------------------------------------------------------------

async def test_messages_filters_and_cursor(client, store, vectors):
    tagged = await seed_chain(store, vectors)

    r = await client.get("/messages", params={"limit": 4})
    assert r.status_code == 200
    first = r.json()
    assert len(first["items"]) == 4 and first["nextCursor"] and first["limit"] == 4

    seen = ids(await page_all(client, limit=4))
    assert len(seen) == len(set(seen)) == len(tagged) == 10
    assert seen[:4] == ids(first["items"])
    positions = [tagged[b] for b in seen]
    assert positions == sorted(positions, reverse=True)  # newest milestone first

    async def only(**params):
        r = await client.get("/messages", params=params)
        assert r.status_code == 200, r.text
        return ids(r.json()["items"])

    assert len(await only(kind="trust.score")) == 3
    assert await only(verdict="MALFORMED") == [next(b for b in tagged
                                                     if b.startswith("0x3ef9a939"))]
    assert await only(ie=IE) == [B370_5]
    assert await only(q="ngsi") == [next(b for b in tagged if b.startswith("0xf4b8b3a3"))]
    assert await only(jsonpath="event=scale") == [
        next(b for b in tagged if b.startswith("0x671ce058"))]
    assert len(await only(ms_from=372, ms_to=372)) == 2
    assert await only(tag="trust.score", ie="nobody:000000000000") == []

    assert (await client.get("/messages", params={"cursor": "not-a-cursor"})).status_code == 400
    for bad in ({"limit": 501}, {"limit": 0}, {"verdict": "BOGUS"}, {"jsonpath": "noequals"},
                {"jsonpath": "a..b=1"}, {"block_id": "0x1234"}, {"block_id": "zz" * 33}):
        assert (await client.get("/messages", params=bad)).status_code == 422, bad


async def test_message_item_shape(client, store, vectors):
    await seed_chain(store, vectors)
    item = (await client.get("/messages", params={"block_id": B370_5})).json()["items"][0]
    assert item["blockId"] == B370_5
    assert item["tag"] == "trust.score" and item["kind"] == "trust.score"
    assert item["verdict"] == verdicts.UNSIGNED_LEGACY
    assert item["ieId"] == IE and item["json"] == {"score": 0.91, "id": IE}
    assert item["msIndex"] == 370 and item["wfIndex"] == 5
    assert item["milestoneAtMs"] == 1791283574000
    assert item["milestoneAt"] == "2026-10-06T10:46:14.000Z"
    assert item["dateMs"] == 1791283574000 and item["date"] == "2026-10-06T10:46:14.000Z"
    assert item["canonHash"] == "0x" + canon.canon_hash({"score": 0.91, "id": IE}).hex()
    assert item["links"]["proof"] == f"/proofs/{B370_5}"
    assert item["links"]["lifecycle"] == f"/messages/{B370_5}/lifecycle"


async def test_search_by_block_id_date_tag(client, store, vectors):
    """The brief's three mandatory criteria: message/block identifier, date and tag."""
    tagged = await seed_chain(store, vectors)
    ms371 = sorted(b for b, i in tagged.items() if i == 371)

    async def found(**params):
        r = await client.get("/messages", params=params)
        assert r.status_code == 200, r.text
        return sorted(ids(r.json()["items"]))

    # by block id, in any hex case
    assert await found(block_id=B370_4) == [B370_4]
    assert await found(block_id="0x" + B370_4[2:].upper()) == [B370_4]
    assert await found(block_id="0x" + "00" * 32) == []

    # by tag
    by_tag = await found(tag="trust.score")
    assert len(by_tag) == 3 and B370_4 in by_tag and B370_5 in by_tag
    assert await found(tag="no.such.tag") == []

    # by date: ISO 8601 (Z or offset) or epoch milliseconds, inclusive on both ends
    iso = "2026-10-06T10:46:19Z"
    assert await found(date_from=iso, date_to=iso) == ms371
    assert await found(date_from="2026-10-06T12:46:19+02:00",
                       date_to="2026-10-06T10:46:19.000+00:00") == ms371
    assert await found(date_from=str(MS371_TS * 1000), date_to=str(MS371_TS * 1000 + 999)) == ms371
    assert await found(date_to="2026-10-05") == []  # a date alone covers that whole day
    assert len(await found(date_from="2026-10-06", date_to="2026-10-06")) == 10

    # combined
    llo_since_371 = await found(tag="LLO-K8s", date_from=iso)
    assert len(llo_since_371) == 3
    assert await found(tag="trust.score", date_from=iso, date_to=iso) == [
        b for b in ms371 if b.startswith("0x32b2ce5c")]

    for bad in ({"date_from": "yesterday"}, {"date_to": "2026-13-01"},
                {"date_from": "2026-10-07", "date_to": "2026-10-06"}):
        assert (await client.get("/messages", params=bad)).status_code == 400, bad
    # digits only count as epoch milliseconds with 11-16 digits; a year or epoch seconds
    # would silently mean 1970
    for digits in ("2026", "20261006", str(MS371_TS), "1" * 17):
        r = await client.get("/messages", params={"date_from": digits})
        assert r.status_code == 400 and "milliseconds" in r.json()["detail"], digits


async def test_message_detail(client, store, vectors):
    await seed_chain(store, vectors)
    data = next(b["data"] for b in vectors("blocks") if b["blockId"] == B370_5)

    r = await client.get(f"/messages/{B370_5}")
    assert r.status_code == 200
    d = r.json()
    assert d["indexed"] is True and d["blockId"] == B370_5
    assert d["dataHex"] == data
    assert d["json"] == {"score": 0.91, "id": IE}
    assert d["submission"] is None
    assert d["checks"]["solid"]["ok"] is None and d["checks"]["content"]["ok"] is None
    assert d["checks"]["solid"]["via"] == "GET /api/core/v2/blocks/{blockId}/metadata"
    assert d["checks"]["content"]["via"] == "GET /api/core/v2/blocks/{blockId}"

    assert (await client.get("/messages/0x" + "ab" * 32)).status_code == 404
    assert (await client.get("/messages/0xabc")).status_code == 422


async def test_out_of_range_timestamps_do_not_break_listing(client, store):
    """A signed `iat` may be any integer up to 2^53-1; it must not take a page down."""
    bid = b"\x61" * 32
    await store.put_message(MessageRow(block_id=bid, tag="trust.score", kind="trust.score",
                                       verdict=verdicts.PRODUCER_SIGNED, iat=2**53 - 1,
                                       received_at_ms=2**62, ms_index=1, wf_index=0, ts=1))
    r = await client.get("/messages")
    assert r.status_code == 200
    item = r.json()["items"][0]
    assert item["issuedAtMs"] == 2**53 - 1 and item["issuedAt"] is None
    assert item["receivedAtMs"] == 2**62 and item["receivedAt"] is None
    assert (await client.get(f"/messages/0x{bid.hex()}")).status_code == 200


# -- lookups ----------------------------------------------------------------------------------

async def test_lookup_canonical(client, store, vectors):
    await seed_chain(store, vectors)
    body = b'{\n  "id" :   "MyDomain:fa163e5e25ef",\n\t"score":0.91 }'
    r = await client.post("/lookup", content=body, headers={"content-type": "application/json"})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["canonHash"] == "0x" + canon.canon_hash({"score": 0.91, "id": IE}).hex()
    assert ids(j["matches"]) == [B370_5]
    assert j["matches"][0]["links"]["proof"] == f"/proofs/{B370_5}"

    miss = await client.post("/lookup", json={"id": IE, "score": 0.9100001})
    assert miss.status_code == 200 and miss.json()["matches"] == []

    # a whole envelope is matched by its body
    env = sealed_score({"id": IE, "score": 0.33}, seq=1)
    bid = await put_signed(store, env, ms_index=400, ts=MS371_TS + 100)
    r = await client.post("/lookup", json=env)
    assert ids(r.json()["matches"]) == ["0x" + bid.hex()]

    bad = await client.post("/lookup", content=b"{not json",
                            headers={"content-type": "application/json"})
    assert bad.status_code == 400
    big = await client.post("/lookup", content=b'{"a":"' + b"x" * 300_000 + b'"}',
                            headers={"content-type": "application/json"})
    assert big.status_code == 413


async def test_lookup_blind(client, store):
    key = b"\x09" * 32
    token = blind_token(key, "ie", IE)
    other = blind_token(key, "tag", "trust.score")
    bid = b"\x42" * 32
    await store.put_message(MessageRow(block_id=bid, tag="trust.score", kind="trust.score",
                                       encrypted=True, verdict=verdicts.PRODUCER_SIGNED,
                                       iss=ISS, ms_index=500, wf_index=1, ts=MS371_TS))
    await store.put_blind(token, bid)
    await store.put_blind(other, bid)

    r = await client.post("/lookup/blind", json={"tokens": [token, "unknown-token"]})
    assert r.status_code == 200, r.text
    matches = r.json()["matches"]
    assert [(m["token"], m["blockId"]) for m in matches] == [(token, "0x" + bid.hex())]
    assert matches[0]["links"]["self"] == "/messages/0x" + bid.hex()

    both = (await client.post("/lookup/blind", json={"tokens": [token, other]})).json()
    assert {m["token"] for m in both["matches"]} == {token, other}

    for bad in ({"tokens": []}, {"tokens": ["x"] * 65}, {"tokens": ["x" * 300]}, {}):
        assert (await client.post("/lookup/blind", json=bad)).status_code == 422, bad


# -- IE lineage and Orion -----------------------------------------------------------------------

async def seed_lineage(store, vectors):
    await seed_chain(store, vectors)
    await put_signed(store, sealed_score({"id": IE, "score": 0.80}, seq=1), ms_index=380,
                     ts=MS371_TS + 60)
    await put_signed(store, sealed_score({"id": IE, "score": 0.42}, seq=2), ms_index=381,
                     ts=MS371_TS + 65)


async def test_ie_list(client, store, vectors):
    await seed_lineage(store, vectors)
    r = await client.get("/ie")
    assert r.status_code == 200
    items = {i["ieId"]: i for i in r.json()["items"]}
    assert set(items) == {IE, "MyDomain:aabbccddeeff", "MyDomain:fa163ed55867"}
    assert items[IE]["count"] == 3 and items[IE]["latestScore"] == 0.42
    assert items[IE]["lastMsIndex"] == 381


async def test_ie_lineage_with_orion_state(client, store, vectors):
    await seed_lineage(store, vectors)
    with respx.mock() as mock:
        route = mock.get(ORION_ENTITY).respond(200, json={
            "id": f"urn:ngsi-ld:InfrastructureElement:{IE}", "type": "InfrastructureElement",
            "trustScore": {"type": "Property", "value": 0.42}})
        r = await client.get(f"/ie/{IE}/lineage")
        assert r.status_code == 200, r.text
        j = r.json()
        assert [e["score"] for e in j["entries"]] == [0.91, 0.80, 0.42]
        assert [e["msIndex"] for e in j["entries"]] == [370, 380, 381]
        assert j["ledger"]["score"] == 0.42 and j["ledger"]["msIndex"] == 381
        assert j["orion"]["status"] == "ok" and j["orion"]["value"] == 0.42
        assert j["drift"] is False
        assert route.called

        route.respond(200, json={"id": "x", "trustScore": {"type": "Property", "value": 0.30}})
        j = (await client.get(f"/ie/{IE}/lineage")).json()
        assert j["orion"]["value"] == 0.30 and j["drift"] is True

        route.respond(404, json={"type": "ResourceNotFound"})
        j = (await client.get(f"/ie/{IE}/lineage")).json()
        assert j["orion"]["status"] == "unknown_entity" and j["drift"] is None

        # the newest entries only; the ledger score still comes from the whole lineage
        j = (await client.get(f"/ie/{IE}/lineage", params={"limit": 2})).json()
        assert [e["score"] for e in j["entries"]] == [0.80, 0.42] and j["total"] == 3

    assert (await client.get("/ie/Nobody:000000000000/lineage")).status_code == 404
    assert (await client.get(f"/ie/{IE}/lineage", params={"limit": 0})).status_code == 422


async def test_orion_unreachable_no_drift(client, store, vectors, settings):
    await seed_lineage(store, vectors)
    with respx.mock() as mock:
        mock.get(ORION_ENTITY).mock(side_effect=httpx.ConnectError("connection refused"))
        j = (await client.get(f"/ie/{IE}/lineage")).json()
    assert j["orion"] == {"status": "unreachable", "value": None,
                          "entityId": f"urn:ngsi-ld:InfrastructureElement:{IE}"}
    assert j["drift"] is None
    assert j["ledger"]["score"] == 0.42

    app = create_app(replace(settings, orion_url=None), store=store)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://w.test") as c:
            j = (await c.get(f"/ie/{IE}/lineage")).json()
    assert j["orion"]["status"] == "not_configured" and j["drift"] is None


# -- flows, incidents, alerts, anchors ----------------------------------------------------------

async def test_flows_and_incidents(client, store, vectors):
    await seed_chain(store, vectors)
    e1 = await put_signed(store, sealed_score({"id": IE, "score": 0.5}, seq=1, corr="c-1"),
                          ms_index=390, ts=MS371_TS + 90)
    e2 = await put_signed(store, sealed_score({"id": IE, "score": 0.6}, seq=2, corr="c-1",
                                              prev="0x" + e1.hex()), ms_index=391,
                          ts=MS371_TS + 95)
    gap_prev = "0x" + "99" * 32
    e3 = await put_signed(store, sealed_score({"id": IE, "score": 0.7}, seq=3, prev=gap_prev),
                          ms_index=392, ts=MS371_TS + 100)

    r = await client.get("/flows", params={"by": "issuer"})
    assert r.status_code == 200
    assert [(f["key"], f["count"]) for f in r.json()["items"]] == [(ISS, 3)]

    r = await client.get(f"/flows/issuer/{ISS}")
    assert r.status_code == 200, r.text
    flow = r.json()
    assert flow["by"] == "issuer" and flow["key"] == ISS
    assert ids(flow["items"]) == ["0x" + b.hex() for b in (e1, e2, e3)]
    assert flow["chain"]["links"] == 1
    assert flow["chain"]["gaps"] == ["0x" + e3.hex()]
    assert flow["chain"]["forks"] == []
    assert flow["total"] == 3

    newest = (await client.get(f"/flows/issuer/{ISS}", params={"limit": 1})).json()
    assert ids(newest["items"]) == ["0x" + e3.hex()] and newest["total"] == 3
    assert newest["chain"]["gaps"] == ["0x" + e3.hex()]  # judged on the whole flow

    corr = (await client.get("/flows/corr/c-1")).json()
    assert ids(corr["items"]) == ["0x" + e1.hex(), "0x" + e2.hex()]
    by_ie = (await client.get("/flows", params={"by": "ie"})).json()["items"]
    assert {f["key"] for f in by_ie} >= {IE}
    assert (await client.get("/flows/bogus/x")).status_code == 422
    assert (await client.get("/flows", params={"by": "bogus"})).status_code == 422

    iid = await store.put_incident(opened_at_ms=MS371_TS * 1000, severity="high",
                                   title="Trust drop on fa163e5e25ef", ie_id=IE)
    await store.attach_incident_event(iid, from_hex(B370_5), "trigger")
    await store.attach_incident_event(iid, e1, "related")
    await store.put_incident(opened_at_ms=MS371_TS * 1000 - 5, severity="low", title="older",
                             status="closed", closed_at_ms=MS371_TS * 1000)

    r = await client.get("/incidents")
    assert r.status_code == 200
    items = r.json()["items"]
    assert [i["title"] for i in items] == ["Trust drop on fa163e5e25ef", "older"]
    assert items[0]["openedAtMs"] == MS371_TS * 1000
    assert items[0]["openedAt"] == "2026-10-06T10:46:19.000Z"
    assert [i["title"] for i in (await client.get(
        "/incidents", params={"status": "closed"})).json()["items"]] == ["older"]

    r = await client.get(f"/incidents/{iid}")
    assert r.status_code == 200
    inc = r.json()
    events = {e["blockId"]: e for e in inc["events"]}
    assert events[B370_5]["role"] == "trigger"
    assert events[B370_5]["verdict"] == verdicts.UNSIGNED_LEGACY
    assert events[B370_5]["links"]["proof"] == f"/proofs/{B370_5}"
    assert events["0x" + e1.hex()]["verdict"] == verdicts.PRODUCER_SIGNED
    assert (await client.get("/incidents/999999")).status_code == 404


async def test_alerts_and_anchors(client, store, vectors):
    await seed_chain(store, vectors)
    bid = from_hex(B370_5)
    await store.put_alert(Alert("FORGED", "critical", bid, None, {"reason": "bad sig"},
                                MS371_TS * 1000))
    await store.put_alert(Alert("STALE", "low", None, IE, {"lastScoreMs": 1}, MS371_TS * 1000 + 1))

    alerts = (await client.get("/alerts")).json()["items"]
    assert [a["rule"] for a in alerts] == ["STALE", "FORGED"]
    forged = alerts[1]
    assert forged["blockId"] == B370_5 and forged["evidence"] == {"reason": "bad sig"}
    assert forged["atMs"] == MS371_TS * 1000 and forged["at"] == "2026-10-06T10:46:19.000Z"
    assert [a["rule"] for a in (await client.get(
        "/alerts", params={"severity": "critical"})).json()["items"]] == ["FORGED"]
    assert [a["rule"] for a in (await client.get(
        "/alerts", params={"block_id": B370_5})).json()["items"]] == ["FORGED"]
    assert [a["rule"] for a in (await client.get(
        "/alerts", params={"ie": IE})).json()["items"]] == ["STALE"]

    ms = vectors("milestones")
    mids = [from_hex(m["milestoneId"]) for m in ms]
    cp = checkpoint.build("private_tangle1", "MyDomain", (370, mids[0]), (373, mids[-1]), mids,
                          10, b"\x01" * 32, None)
    await store.put_anchor(seq=1, from_ms=370, to_ms=373, ms_root=from_hex(cp["msRoot"]),
                           checkpoint=cp, checkpoint_hash=checkpoint.hash(cp),
                           network="testnet", created_at_ms=MS371_TS * 1000 + 30_000,
                           tx="5xGp7rWq2Tz9", record=3, status="anchored")
    anchors = (await client.get("/anchors")).json()["items"]
    assert len(anchors) == 1
    a = anchors[0]
    assert (a["seq"], a["fromMilestone"], a["toMilestone"], a["status"]) == (1, 370, 373,
                                                                             "anchored")
    assert a["msRoot"] == cp["msRoot"] and a["checkpoint"] == cp
    assert a["checkpointHash"] == "0x" + checkpoint.hash(cp).hex()
    assert a["record"] == 3 and a["tx"] == "5xGp7rWq2Tz9" and a["network"] == "testnet"
    assert a["createdAt"] == "2026-10-06T10:46:49.000Z"


# -- identity, verifier config, milestones, stats -----------------------------------------------

async def test_identity_proxies_anchor_and_policy(client, store, settings, tmp_path):
    identities = {"network": "testnet", "identities": [
        {"name": "relay", "did": "did:iota:testnet:0x01", "keys": [
            {"kid": "did:iota:testnet:0x01#sig-1", "type": "Ed25519",
             "publicKeyHex": "0x" + "11" * 32}]}], "previous": []}
    with respx.mock() as mock:
        mock.get(f"{ANCHOR}/identities").respond(200, json=identities)
        r = await client.get("/identity")
        assert r.status_code == 200
        j = r.json()
        assert j["anchor"]["status"] == "ok"
        assert j["anchor"]["identities"] == identities["identities"]
        assert j["anchor"]["network"] == "testnet"
        assert j["policy"] is None

        mock.get(f"{ANCHOR}/identities").mock(side_effect=httpx.ConnectTimeout("slow"))
        j = (await client.get("/identity")).json()
        assert j["anchor"]["status"] == "unreachable" and j["anchor"]["identities"] == []

    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({"version": 3, "tags": {
        "trust.score": {"allowed": [ISS], "require_signature": True, "legacy_grace": False}}}))
    app = create_app(replace(settings, policy_path=str(policy_file), anchor_url=None),
                     store=store)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://w.test") as c:
            j = (await c.get("/identity")).json()
    assert j["anchor"]["status"] == "not_configured"
    assert j["policy"]["version"] == 3
    assert j["policy"]["hash"].startswith("0x") and len(j["policy"]["hash"]) == 66
    assert j["policy"]["tags"]["trust.score"] == {
        "allowed": [ISS], "requireSignature": True, "legacyGrace": False}


async def test_config_verifier(client, vectors):
    r = await client.get("/config/verifier")
    assert r.status_code == 200
    assert r.json() == {
        "bundleVersion": 1,
        "network": "private_tangle1",
        "trustedCoordinatorKeys": vectors("coordinator_keys")["publicKeys"],
        "threshold": 2,
        "rebasedNetwork": "testnet",
        "trailId": "0x" + "7a" * 32,
    }


async def test_milestones_range(client, store, vectors):
    tagged = await seed_chain(store, vectors)
    expected = [m["milestoneId"] for m in vectors("milestones")]
    r = await client.get("/milestones", params={"from": 370, "to": 373})
    assert r.status_code == 200
    assert r.json() == {"from": 370, "to": 373, "ids": expected, "complete": True,
                        "msgCount": len(tagged)}
    assert len(tagged) > 0
    partial = (await client.get("/milestones", params={"from": 369, "to": 373})).json()
    assert partial["ids"] == expected and partial["complete"] is False
    one = (await client.get("/milestones", params={"from": 371, "to": 371})).json()
    assert one["msgCount"] == sum(1 for idx in tagged.values() if idx == 371)
    # Submissions not yet confirmed by a milestone are not counted.
    assert (await client.get("/milestones", params={"from": 374, "to": 380})).json()[
        "msgCount"] == 0
    assert (await client.get("/milestones", params={"from": 373, "to": 370})).status_code == 422
    assert (await client.get("/milestones",
                             params={"from": 1, "to": 1_000_000})).status_code == 422


async def test_stats_and_health(client, store, vectors):
    await seed_chain(store, vectors)
    stats = (await client.get("/stats")).json()
    assert stats["counts"]["messages"] == 10 and stats["counts"]["milestones"] == 4
    assert stats["counts"]["cursor"] == 0
    assert stats["validator"]["running"] is False
    assert stats["nodeRoute"] == {"enabled": False, "route": None, "registered": False,
                                  "error": None}

    # counts are cached for a few seconds: polling dashboards do not hammer the database
    await store.put_message(MessageRow(block_id=b"\x71" * 32, tag="t", ms_index=1, ts=1))
    assert (await client.get("/stats")).json()["counts"]["messages"] == 10

    health = await client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["status"] == "ok" and health.json()["db"] == "ok"


async def test_cors_for_console_origin(client):
    pre = await client.options("/messages", headers={
        "Origin": "http://console.test", "Access-Control-Request-Method": "GET"})
    assert pre.headers.get("access-control-allow-origin") == "http://console.test"
    r = await client.get("/config/verifier", headers={"Origin": "http://evil.test"})
    assert "access-control-allow-origin" not in r.headers


async def test_openapi_lists_all_routes(client):
    r = await client.get("/openapi.json")
    assert r.status_code == 200
    spec = r.json()
    paths = spec["paths"]
    expected = {
        ("/messages", "get"), ("/messages/{block_id}", "get"),
        ("/messages/{block_id}/lifecycle", "get"), ("/messages/{block_id}/verify", "post"),
        ("/lookup", "post"), ("/lookup/blind", "post"), ("/ie", "get"),
        ("/ie/{ie_id}/lineage", "get"), ("/proofs/{block_id}", "get"), ("/milestones", "get"),
        ("/config/verifier", "get"), ("/alerts", "get"), ("/anchors", "get"),
        ("/identity", "get"), ("/flows", "get"), ("/flows/{by}/{key}", "get"),
        ("/incidents", "get"), ("/incidents/{incident_id}", "get"), ("/stats", "get"),
        ("/stream", "get"), ("/ingest", "post"), ("/healthz", "get"),
    }
    present = {(p, m) for p, ops in paths.items() for m in ops}
    assert expected <= present, expected - present
    for path, method in expected:
        op = paths[path][method]
        assert op.get("tags"), (path, method)
        assert op.get("summary"), (path, method)
    proof_doc = paths["/proofs/{block_id}"]["get"]["description"]
    assert "envelope.verdict" in proof_doc and "recomputes" in proof_doc
    params = {p["name"] for p in paths["/messages"]["get"]["parameters"]}
    assert {"block_id", "tag", "date_from", "date_to", "cursor", "limit"} <= params
    assert (await client.get("/docs")).status_code == 200
