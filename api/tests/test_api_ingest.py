import asyncio
import json
from dataclasses import replace

import httpx
import respx
from conftest import HORNET, TOKEN
from witness_api.app import create_app
from witness_core.codec import serialize_tagged_block
from witness_core.ids import blake2b256, to_hex
from witness_indexer.hornet_rest import RAW_MEDIA_TYPE

MSG = {"score": 0.5, "id": "MyDomain:aabbccddeeff"}
PARENTS = [b"\x11" * 32, b"\x22" * 32]
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def make_block(message=MSG, tag="trust.score"):
    data = json.dumps(message).encode()
    raw = serialize_tagged_block(PARENTS, tag.encode(), data)
    return raw, blake2b256(raw), data


def record(sub_id, bid, data, tag="trust.score", **over):
    r = {
        "subId": sub_id, "receivedAtMs": 1_791_283_570_000, "tag": tag, "message": MSG,
        "dataHex": None if data is None else to_hex(data),
        "blockId": None if bid is None else to_hex(bid), "hornetStatus": 201,
        "relay": {"verdict": "RELAY_ATTESTED", "iss": "did:iota:testnet:0x01", "seq": 4},
    }
    r.update(over)
    return r


def metadata(bid, ms=None):
    m = {"blockId": to_hex(bid), "parents": [to_hex(p) for p in PARENTS], "isSolid": True,
         "shouldReattach": False}
    if ms is not None:
        m.update(referencedByMilestoneIndex=ms, ledgerInclusionState="noTransaction",
                 whiteFlagIndex=3)
    return m


def hornet(mock, bid, raw, ms=371):
    path = f"{HORNET}/api/core/v2/blocks/{to_hex(bid)}"
    meta = mock.get(f"{path}/metadata").respond(200, json=metadata(bid, ms))
    block = mock.get(path, headers={"Accept": RAW_MEDIA_TYPE}).respond(
        200, content=raw, headers={"Content-Type": RAW_MEDIA_TYPE})
    return meta, block


async def test_ingest_requires_token(client, store, settings):
    _, bid, data = make_block()
    rec = record("sub-1", bid, data)
    assert (await client.post("/ingest", json=rec)).status_code == 401
    wrong = await client.post("/ingest", json=rec, headers={"Authorization": "Bearer nope"})
    assert wrong.status_code == 401
    basic = await client.post("/ingest", json=rec, headers={"Authorization": f"Basic {TOKEN}"})
    assert basic.status_code == 401
    assert await store.submission(sub_id="sub-1") is None

    ok = await client.post("/ingest", json=rec, headers=AUTH)
    assert ok.status_code == 202, ok.text
    assert ok.json() == {"accepted": True, "duplicate": False, "subId": "sub-1",
                         "blockId": to_hex(bid), "status": "SUBMITTED"}

    # without a configured token the HTTP fallback is closed
    app = create_app(replace(settings, ingest_token=None), store=store)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://w.test") as c:
            r = await c.post("/ingest", json=record("sub-2", None, None), headers=AUTH)
    assert r.status_code == 403


async def test_ingest_dedupe(client, store):
    _, bid, data = make_block()
    first = await client.post("/ingest", json=record("sub-1", bid, data), headers=AUTH)
    assert first.status_code == 202
    again = await client.post("/ingest", json=record("sub-1", bid, data), headers=AUTH)
    assert again.status_code == 200
    assert again.json()["duplicate"] is True and again.json()["accepted"] is False
    # the same block forwarded again under another submission id (e.g. MQTT got there first)
    other = await client.post("/ingest", json=record("mqtt-77", bid, data), headers=AUTH)
    assert other.status_code == 200 and other.json()["duplicate"] is True
    assert (await store.stats())["submissions"] == 1
    statuses = [r["status"] for r in await store.lifecycle(bid)]
    assert statuses == ["RECEIVED", "SUBMITTED"]
    events = await store.events_after(0, 10)
    assert [e["type"] for e in events] == ["submission"]

    failed = await client.post("/ingest", json=record("sub-9", None, None, hornetStatus=503),
                               headers=AUTH)
    assert failed.status_code == 202 and failed.json()["status"] == "RECEIVED"


async def test_ingested_block_is_validated_in_the_background(store, settings):
    """With the worker on, an HTTP-ingested block walks to CONTENT_VERIFIED by itself."""
    raw, bid, data = make_block()
    app = create_app(replace(settings, validate=True), store=store)
    with respx.mock() as mock:
        meta, block = hornet(mock, bid, raw)
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://w.test") as c:
                assert (await c.get("/stats")).json()["validator"]["running"] is True
                r = await c.post("/ingest", json=record("sub-1", bid, data), headers=AUTH)
                assert r.status_code == 202
                for _ in range(100):
                    lc = (await c.get(f"/messages/{to_hex(bid)}/lifecycle")).json()
                    if lc["status"] == "CONTENT_VERIFIED":
                        break
                    await asyncio.sleep(0.05)
    assert lc["status"] == "CONTENT_VERIFIED"
    assert lc["checks"]["solid"]["ok"] is True and lc["checks"]["content"]["ok"] is True
    assert meta.called and block.called


async def test_ingest_rejects_malformed(client):
    _, bid, data = make_block()
    bad = record("sub-1", bid, None)  # a block id without the bytes that were sent
    r = await client.post("/ingest", json=bad, headers=AUTH)
    assert r.status_code == 400 and "dataHex" in r.json()["detail"]
    missing = {k: v for k, v in record("sub-2", bid, data).items() if k != "relay"}
    assert (await client.post("/ingest", json=missing, headers=AUTH)).status_code == 400
    for body in (b"[1, 2]", b"{nope", b'"string"'):
        r = await client.post("/ingest", content=body, headers={**AUTH,
                              "content-type": "application/json"})
        assert r.status_code == 400, body
    deep = await client.post("/ingest", content=b'{"a":' + b"[" * 2500 + b"]" * 2500 + b"}",  # 2501 levels
                             headers={**AUTH, "content-type": "application/json"})
    assert deep.status_code == 400
    assert deep.json()["detail"] == "body is JSON nested deeper than 2500 levels"
    huge = record("sub-3", None, None, message={"x": "y" * 600_000})
    assert (await client.post("/ingest", json=huge, headers=AUTH)).status_code == 413


async def test_verify_endpoint_runs_checks(client, store):
    raw, bid, data = make_block()
    assert (await client.post("/ingest", json=record("sub-1", bid, data),
                              headers=AUTH)).status_code == 202
    with respx.mock() as mock:
        meta, block = hornet(mock, bid, raw)
        r = await client.post(f"/messages/{to_hex(bid)}/verify")
        assert r.status_code == 200, r.text
        assert meta.called and block.called
    v = r.json()
    assert v["blockId"] == to_hex(bid)
    assert v["status"] == "CONTENT_VERIFIED" and v["concluded"] is True
    assert v["timedOut"] is False
    solid, content = v["checks"]["solid"], v["checks"]["content"]
    assert solid["check"] == "c" and solid["ok"] is True and solid["isSolid"] is True
    assert solid["referencedByMilestoneIndex"] == 371
    assert solid["ledgerInclusionState"] == "noTransaction"
    assert content["check"] == "d" and content["ok"] is True and content["result"] == "MATCH"
    assert [c["outcome"] for c in v["calls"]] == ["answered", "answered"]
    assert v["calls"][0]["request"] == f"GET /api/core/v2/blocks/{to_hex(bid)}/metadata"
    assert v["calls"][1]["request"] == f"GET /api/core/v2/blocks/{to_hex(bid)}"
    assert v["calls"][1]["bytes"] == len(raw)
    assert v["startedAtMs"] <= v["finishedAtMs"]
    assert v["cached"] is False

    # asked again within the cooldown: the stored checks, without bothering the node
    with respx.mock(assert_all_called=False) as mock:
        meta, block = hornet(mock, bid, raw)
        again = (await client.post(f"/messages/{to_hex(bid)}/verify")).json()
        assert not meta.called and not block.called
    assert again["cached"] is True and again["calls"] == []
    assert again["status"] == "CONTENT_VERIFIED" and again["concluded"] is True
    assert again["checks"]["solid"]["ok"] is True and again["checks"]["content"]["ok"] is True
    [stored] = await store.validations(bid)
    assert again["checks"]["solid"]["checkedAtMs"] == stored["checked_at_ms"]


async def test_verify_after_cooldown_asks_the_node_again(store, settings):
    raw, bid, data = make_block()
    app = create_app(replace(settings, verify_cooldown_s=0), store=store)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://w.test") as c:
            await c.post("/ingest", json=record("sub-1", bid, data), headers=AUTH)
            with respx.mock() as mock:
                meta, block = hornet(mock, bid, raw)
                first = (await c.post(f"/messages/{to_hex(bid)}/verify")).json()
                again = (await c.post(f"/messages/{to_hex(bid)}/verify")).json()
                assert meta.call_count == 2 and block.call_count == 2
    assert first["cached"] is False and again["cached"] is False
    assert again["status"] == "CONTENT_VERIFIED" and again["checks"]["content"]["ok"] is True
    assert len(await store.validations(bid)) == 2  # every answer is kept


async def test_verify_is_throttled_and_can_require_a_token(store, settings):
    """At most `verify_concurrency` checks run at once (429 beyond); with
    WITNESS_VERIFY_TOKEN set, only bearers of it may trigger node calls."""
    raw1, bid1, data1 = make_block()
    _, bid2, data2 = make_block({"score": 0.25, "id": MSG["id"]})
    token = "verify-token-0123456789"
    app = create_app(replace(settings, verify_concurrency=1, verify_token=token), store=store)
    held = asyncio.Event()
    entered = asyncio.Event()

    async def slow_metadata(request):
        entered.set()
        await held.wait()
        return httpx.Response(200, json=metadata(bid1, 371))

    bearer = {"Authorization": f"Bearer {token}"}
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://w.test") as c:
            for sub, bid, data in (("s1", bid1, data1), ("s2", bid2, data2)):
                await c.post("/ingest", json=record(sub, bid, data), headers=AUTH)
            assert (await c.post(f"/messages/{to_hex(bid1)}/verify")).status_code == 401
            wrong = {"Authorization": "Bearer nope"}
            assert (await c.post(f"/messages/{to_hex(bid1)}/verify",
                                 headers=wrong)).status_code == 401
            with respx.mock(assert_all_called=False) as mock:
                path = f"{HORNET}/api/core/v2/blocks/{to_hex(bid1)}"
                mock.get(f"{path}/metadata").mock(side_effect=slow_metadata)
                mock.get(path).respond(200, content=raw1,
                                       headers={"Content-Type": RAW_MEDIA_TYPE})
                busy = asyncio.create_task(c.post(f"/messages/{to_hex(bid1)}/verify",
                                                  headers=bearer))
                await asyncio.wait_for(entered.wait(), 5)
                r = await c.post(f"/messages/{to_hex(bid2)}/verify", headers=bearer)
                assert r.status_code == 429
                assert int(r.headers["retry-after"]) >= 1
                held.set()
                assert (await busy).status_code == 200
            # reads stay open without the token
            assert (await c.get(f"/messages/{to_hex(bid1)}/lifecycle")).status_code == 200


async def test_verify_reports_content_mismatch(client, store):
    raw, bid, _ = make_block()
    sent = json.dumps({"score": 0.9, "id": MSG["id"]}).encode()  # not what the block carries
    await client.post("/ingest", json=record("sub-1", bid, sent), headers=AUTH)
    with respx.mock() as mock:
        hornet(mock, bid, raw)
        v = (await client.post(f"/messages/{to_hex(bid)}/verify")).json()
    assert v["status"] == "CONTENT_MISMATCH"
    content = v["checks"]["content"]
    assert content["ok"] is False and content["result"] == "MISMATCH"
    assert [f["field"] for f in content["diff"]["fields"]] == ["data"]
    assert content["diff"]["json"]["changes"][0]["path"] == "$.score"


async def test_verify_when_node_unreachable_or_block_unknown(client, store, settings):
    _, bid, data = make_block()
    await client.post("/ingest", json=record("sub-1", bid, data), headers=AUTH)
    with respx.mock() as mock:
        mock.get(url__startswith=HORNET).mock(side_effect=httpx.ConnectError("refused"))
        v = (await client.post(f"/messages/{to_hex(bid)}/verify")).json()
    assert v["concluded"] is False and v["status"] == "SUBMITTED"
    assert v["checks"]["solid"]["ok"] is None and v["checks"]["content"]["ok"] is None
    assert {c["outcome"] for c in v["calls"]} == {"unavailable"}
    assert v["timedOut"] is True
    assert all("hornet.test" not in c["error"] for c in v["calls"])  # node address stays private

    assert (await client.post("/messages/0x" + "cd" * 32 + "/verify")).status_code == 404

    app = create_app(replace(settings, hornet_url=None), store=store)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://w.test") as c:
            r = await c.post(f"/messages/{to_hex(bid)}/verify")
    assert r.status_code == 503


async def test_lifecycle_endpoint(client, store):
    raw, bid, data = make_block()
    await client.post("/ingest", json=record("sub-1", bid, data), headers=AUTH)
    pending = (await client.get(f"/messages/{to_hex(bid)}/lifecycle")).json()
    assert pending["status"] == "SUBMITTED"
    assert pending["checks"]["solid"]["ok"] is None

    with respx.mock() as mock:
        hornet(mock, bid, raw)
        await client.post(f"/messages/{to_hex(bid)}/verify")

    r = await client.get(f"/messages/{to_hex(bid)}/lifecycle")
    assert r.status_code == 200
    lc = r.json()
    assert lc["blockId"] == to_hex(bid) and lc["status"] == "CONTENT_VERIFIED"
    assert [t["status"] for t in lc["transitions"]] == [
        "RECEIVED", "SUBMITTED", "SOLID", "CONFIRMED", "CONTENT_VERIFIED"]
    first = lc["transitions"][0]
    assert first["subId"] == "sub-1" and first["at"].endswith("Z") and first["atMs"] > 0
    assert lc["transitions"][3]["detail"]["referencedByMilestoneIndex"] == 371
    assert len(lc["validations"]) == 1 and lc["validations"][0]["isSolid"] is True
    assert [c["result"] for c in lc["contentChecks"]] == ["MATCH"]
    assert lc["checks"]["solid"]["ok"] is True
    assert lc["checks"]["solid"]["referencedByMilestoneIndex"] == 371
    assert lc["checks"]["content"]["ok"] is True and lc["checks"]["content"]["result"] == "MATCH"
    assert lc["submission"]["subId"] == "sub-1" and lc["submission"]["source"] == "http"
    assert lc["submission"]["dataHex"] == to_hex(data)

    # the message detail carries the same two brief checks, even before the indexer saw it
    d = (await client.get(f"/messages/{to_hex(bid)}")).json()
    assert d["indexed"] is False and d["status"] == "CONTENT_VERIFIED"
    assert d["checks"]["solid"]["ok"] is True and d["checks"]["content"]["ok"] is True

    assert (await client.get("/messages/0x" + "ef" * 32 + "/lifecycle")).status_code == 404


async def test_lifecycle_pages_validations(client, store):
    """Every metadata answer is kept, so validations are served newest page first."""
    _, bid, data = make_block()
    await client.post("/ingest", json=record("sub-1", bid, data), headers=AUTH)
    for i in range(120):
        await store.put_validation(bid, 1_000 + i, i >= 100, 371 if i == 119 else None,
                                   "noTransaction" if i == 119 else None, False)
    url = f"/messages/{to_hex(bid)}/lifecycle"
    page = (await client.get(url)).json()
    assert [v["checkedAtMs"] for v in page["validations"]] == list(range(1_070, 1_120))
    assert page["validationsCursor"]
    assert page["checks"]["solid"]["checkedAtMs"] == 1_119  # always the latest answer
    assert page["checks"]["solid"]["referencedByMilestoneIndex"] == 371

    older = (await client.get(url, params={"cursor": page["validationsCursor"]})).json()
    assert [v["checkedAtMs"] for v in older["validations"]] == list(range(1_020, 1_070))
    oldest = (await client.get(url, params={"cursor": older["validationsCursor"],
                                            "limit": 30})).json()
    assert [v["checkedAtMs"] for v in oldest["validations"]] == list(range(1_000, 1_020))
    assert oldest["validationsCursor"] is None

    assert (await client.get(url, params={"cursor": "x"})).status_code == 422
    assert (await client.get(url, params={"limit": 501})).status_code == 422


SECRET = {"reportId": "r-41", "secret": "s0123456789abcdef"}


def sealed_block():
    """What the relay posts for a legacy audit.report on an encrypted tag: ciphertext only."""
    env = {"w": 1, "tag": "audit.report", "iss": "did:iota:testnet:0x01", "kid": "k", "seq": 1,
           "iat": 1, "nonce": "n", "att": {"mode": "relay", "sub": "anonymous"},
           "enc": {"protected": "e30", "ciphertext": "AAAA", "recipients": []},
           "bix": ["tok"], "sig": "x"}
    return make_block(env, tag="audit.report")


def no_plaintext(answer: dict) -> None:
    text = json.dumps(answer)
    assert "r-41" not in text and "s0123456789abcdef" not in text, answer


async def test_sealed_legacy_plaintext_is_never_served(client, store):
    from witness_indexer.store import MessageRow, Submission

    # Forwarded by the relay as sealed: nothing to store but the ciphertext.
    _, bid, data = sealed_block()
    rec = record("sub-s", bid, data, tag="audit.report", message=None, messageSealed=True)
    assert (await client.post("/ingest", json=rec, headers=AUTH)).status_code == 202
    pre = (await client.get(f"/messages/{to_hex(bid)}")).json()
    assert pre["indexed"] is False and pre.get("content") is None
    assert pre["submission"].get("message") is None
    no_plaintext(pre)

    # A row an older relay forwarded with the plaintext still in it: not served, before or
    # after the block is indexed.
    _, old, old_data = make_block({**json.loads(data), "seq": 2}, tag="audit.report")
    await store.put_submission(Submission(
        sub_id="sub-old", source="mqtt", received_at_ms=1_791_283_570_000, tag="audit.report",
        message_json=SECRET, data_hex=to_hex(old_data), block_id=old))
    no_plaintext((await client.get(f"/messages/{to_hex(old)}")).json())
    await store.put_message(MessageRow(block_id=old, tag="audit.report", kind="audit.report",
                                       data=old_data, verdict="RELAY_ATTESTED", encrypted=True,
                                       ms_index=1, ts=1_791_283_571))
    indexed = (await client.get(f"/messages/{to_hex(old)}")).json()
    assert indexed["indexed"] is True and indexed["submission"].get("message") is None
    no_plaintext(indexed)

    # An unsealed submission keeps its message.
    _, plain, plain_data = make_block()
    await client.post("/ingest", json=record("sub-p", plain, plain_data), headers=AUTH)
    assert (await client.get(f"/messages/{to_hex(plain)}")).json()["submission"]["message"] == MSG
