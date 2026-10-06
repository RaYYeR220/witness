import asyncio

import psycopg
import pytest
from witness_indexer.store import Alert, MessageFilter, MessageRow, Store, Submission


def bid(n: int) -> bytes:
    return n.to_bytes(32, "big")


def row(n: int, **kw) -> MessageRow:
    base = {
        "block_id": bid(n), "tag": "aeriOS", "kind": "event", "data": b"\x01", "json": {"n": n},
        "ie_id": "ie-a", "canon_hash": bid(1000 + n), "iss": "did:a", "kid": "k1", "seq": n, "iat": n,
        "verdict": "OK", "encrypted": False, "ms_index": n // 10, "wf_index": n % 10, "ts": 1000 + n,
    }
    base.update(kw)
    return MessageRow(**base)


async def test_migrate_idempotent(store: Store):
    await store.migrate()
    await store.migrate()
    assert await store.applied_versions() == [1, 2]


async def test_service_status_in_stats(store: Store):
    assert "orion" not in await store.stats()
    await store.set_service_status("orion", "unreachable", detail="refused", at_ms=5)
    await store.set_service_status("orion", "ok", at_ms=6)
    await store.set_service_status("anchor", "unreachable", at_ms=7)
    st = await store.stats()
    assert (st["orion"], st["anchor"]) == ("ok", "unreachable")
    assert (await store.service_status())["orion"] == {"status": "ok", "detail": None, "at_ms": 6}
    with pytest.raises(ValueError):
        await store.set_service_status("messages", "ok")


async def test_rule_queries(store: Store):
    ok = ["PRODUCER_SIGNED"]
    for n, (seq, prev, verdict) in enumerate(
            [(1, None, "PRODUCER_SIGNED"), (2, bid(1), "PRODUCER_SIGNED"), (3, bid(1), "FORGED"),
             (4, bid(2), "PRODUCER_SIGNED")], start=1):
        await store.put_message(row(n, iss="did:x", seq=seq, prev=prev, verdict=verdict,
                                    kind="trust.score", json={"score": n / 10, "id": "D:1"},
                                    ie_id="D:1", ms_index=n, wf_index=0, ts=100 * n))
    assert (await store.chain_head("did:x", 4, ok, bid(4)))["block_id"] == bid(2)
    assert await store.chain_head("did:x", 1, ok, bid(1)) is None
    assert [r["block_id"] for r in await store.chain_siblings("did:x", bid(1), ok, bid(2))] == []
    assert [r["block_id"] for r in
            await store.chain_siblings("did:x", bid(1), ok + ["FORGED"], bid(2))] == [bid(3)]
    prev = await store.previous_score("D:1", ok, (4, 0), bid(4))
    assert (prev["block_id"], prev["score"]) == (bid(2), 0.2)
    assert (await store.previous_score("D:1", ok, None, bid(9)))["block_id"] == bid(4)
    assert [(r["ie_id"], r["score"]) for r in await store.latest_scores(ok)] == [("D:1", 0.4)]
    # a score that is not a number in [0, 1] is never read as one
    await store.put_message(row(5, iss="did:x", seq=5, verdict="PRODUCER_SIGNED",
                                kind="trust.score", json={"score": "high", "id": "D:1"},
                                ie_id="D:1", ms_index=5, wf_index=0, ts=500))
    await store.put_message(row(6, iss="did:x", seq=6, verdict="PRODUCER_SIGNED",
                                kind="trust.score", json={"score": 7, "id": "D:1"},
                                ie_id="D:1", ms_index=6, wf_index=0, ts=600))
    assert [r["score"] for r in await store.latest_scores(ok)] == [0.4]
    assert await store.missing_messages([bid(1), bid(77), bid(2)]) == [bid(77)]
    assert await store.missing_messages([]) == []
    assert await store.latest_milestone_ts() is None
    assert await store.first_submission_ms() is None
    assert not await store.has_alert("SHADOW", block_id=bid(1))
    await store.put_alert(Alert("SHADOW", "high", bid(1), None, {}, 1))
    assert await store.has_alert("SHADOW", block_id=bid(1))
    assert not await store.has_alert("SHADOW", ie_id="D:1")


async def test_reprocess_milestone_idempotent(store: Store):
    args = (7, bid(7), 111, b"ess", [{"k": 1}], bid(8), bid(6))
    assert await store.put_milestone(*args) is True
    assert await store.put_milestone(*args) is False
    assert await store.put_block(bid(1), 7, 0, b"raw", 5) is True
    assert await store.put_block(bid(1), 7, 0, b"raw", 5) is False
    assert await store.put_message(row(70, ms_index=7, wf_index=0)) == "inserted"
    assert await store.put_message(row(70, ms_index=7, wf_index=0)) is None
    al = Alert("r1", "high", bid(70), "ie-a", {"x": 1}, 5)
    assert await store.put_alert(al) is True
    assert await store.put_alert(al) is False
    st = await store.stats()
    assert (st["milestones"], st["blocks"], st["messages"], st["alerts"]) == (1, 1, 1, 1)
    # callers emit only for new rows
    for r in (row(70), row(71)):
        if await store.put_message(r) == "inserted":
            await store.emit("message", {})
    assert len(await store.events_after(0, 100)) == 1


async def test_pagination_stable(store: Store):
    for n in range(250):
        await store.put_message(row(n, ms_index=n // 7, wf_index=n % 7, ts=n))
    seen, cur, pages = [], None, 0
    while True:
        items, cur = await store.query_messages(MessageFilter(), cur, 100)
        pages += 1
        seen += [i["block_id"] for i in items]
        if cur is None:
            break
    assert pages == 3
    assert len(seen) == len(set(seen)) == 250
    everything = (await store.query_messages(MessageFilter(), None, 250))[0]
    keys = [(r["ms_index"], r["wf_index"]) for r in everything]
    assert keys == sorted(keys, reverse=True)


async def test_unconfirmed_first_then_indexed(store: Store):
    await store.put_message(row(1, ms_index=5, wf_index=1))
    await store.put_message(row(2, ms_index=None, wf_index=None, received_at_ms=50))
    await store.put_message(row(3, ms_index=None, wf_index=None, received_at_ms=90))
    items, _ = await store.query_messages(MessageFilter(), None, 10)
    assert [i["block_id"] for i in items] == [bid(3), bid(2), bid(1)]
    first, cur = await store.query_messages(MessageFilter(), None, 2)
    rest, end = await store.query_messages(MessageFilter(), cur, 2)
    assert [i["block_id"] for i in first + rest] == [bid(3), bid(2), bid(1)]
    assert end is None


async def test_filters(store: Store):
    await store.put_message(row(
        1, tag="a", ie_id="x", verdict="OK", ts=100, received_at_ms=100,
        json={"p": {"q": "v1"}, "t": "alpha beta"}))
    await store.put_message(row(
        2, tag="b", ie_id="y", verdict="BAD", kind="k2", ts=200, received_at_ms=200,
        iss="did:z", json={"p": {"q": "v2"}, "t": "gamma"}))

    async def ids(**kw):
        items, _ = await store.query_messages(MessageFilter(**kw), None, 50)
        return sorted(i["block_id"] for i in items)

    assert await ids(tag="a") == [bid(1)]
    assert await ids(ie="y") == [bid(2)]
    assert await ids(verdict="BAD") == [bid(2)]
    assert await ids(kind="k2") == [bid(2)]
    assert await ids(iss="did:z") == [bid(2)]
    assert await ids(block_id=bid(1)) == [bid(1)]
    assert await ids(t_from=150) == [bid(2)]
    assert await ids(t_to=150) == [bid(1)]
    assert await ids(date_from_ms=150) == [bid(2)]
    assert await ids(date_to_ms=150) == [bid(1)]
    assert await ids(ms_from=0, ms_to=0) == [bid(1), bid(2)]
    assert await ids(q="gamma") == [bid(2)]
    assert await ids(q="alpha") == [bid(1)]
    assert await ids(jsonpath_eq=("p.q", "v2")) == [bid(2)]
    assert await ids(tag="a", ie="y") == []


async def test_lookup_canon_and_blind(store: Store):
    await store.put_message(row(1))
    await store.put_message(row(2))
    await store.put_blind("tok1", bid(1))
    await store.put_blind("tok1", bid(1))
    await store.put_blind("tok2", bid(2))
    assert [r["block_id"] for r in await store.lookup_canon(bid(1001))] == [bid(1)]
    got = await store.lookup_blind(["tok1", "tok2", "nope"])
    assert sorted(r["block_id"] for r in got) == [bid(1), bid(2)]


async def test_cone_order(store: Store):
    for wf, n in [(2, 1), (0, 2), (1, 3)]:
        await store.put_block(bid(n), 9, wf, b"r", 5)
    assert await store.cone_ids(9) == [bid(2), bid(3), bid(1)]


async def test_concurrent_reader(store: Store):
    other = await Store.open(store.dsn, schema=store.schema)
    try:
        await store.put_message(row(1))
        assert (await other.get_message(bid(1)))["block_id"] == bid(1)
        await store.put_message(row(2))
        assert (await other.stats())["messages"] == 2
    finally:
        await other.close()


async def test_cursor_and_milestones(store: Store):
    assert await store.get_cursor() == 0
    await store.set_cursor(5)
    await store.set_cursor(9)
    assert await store.get_cursor() == 9
    await store.put_milestone(3, bid(3), 1, b"e", [], bid(0), bid(2))
    await store.put_milestone(4, bid(4), 2, b"e", [], bid(0), bid(3))
    assert (await store.milestone(3))["id"] == bid(3)
    assert await store.milestone(99) is None
    assert await store.milestone_ids(3, 4) == [bid(3), bid(4)]


async def test_issuer_state_and_ie(store: Store):
    await store.put_message(row(1, seq=1, nonce="a", verdict="PRODUCER_SIGNED"))
    await store.put_message(row(2, seq=2, nonce="b", verdict="RELAY_ATTESTED"))
    seq, nonces = await store.issuer_state("did:a")
    assert seq == 2 and nonces == {"a", "b"}
    assert await store.issuer_state("none") == (None, set())
    assert await store.put_ie_score("ie-a", 1, 1, 0.5, bid(1), "OK") is True
    assert await store.put_ie_score("ie-a", 1, 1, 0.5, bid(1), "OK") is False
    assert [r["ie_id"] for r in await store.ie_list()] == ["ie-a"]
    assert len(await store.ie_lineage("ie-a")) == 2


async def test_submission_dedupe(store: Store):
    base = {"received_at_ms": 1, "tag": "t", "message_json": {"a": 1}, "data_hex": "00",
                "block_id": bid(5), "hornet_status": 200, "relay_verdict": "OK", "iss": "did:a", "seq": 1}
    assert await store.put_submission(Submission(sub_id="s1", source="mqtt", **base)) is True
    assert await store.put_submission(Submission(sub_id="s2", source="http", **base)) is False
    assert await store.put_submission(Submission(sub_id="s1", source="mqtt", **base)) is False
    assert (await store.stats())["submissions"] == 1
    # rows without a block id never collide on it
    for sid in ("n1", "n2"):
        sub = Submission(sub_id=sid, source="http", received_at_ms=2)
        assert await store.put_submission(sub) is True


async def test_listen_notify(store: Store):
    got = asyncio.create_task(anext(store.listen()))
    await asyncio.sleep(0.5)
    eid = await store.emit("message", {"x": 1})
    assert await asyncio.wait_for(got, 5) == eid
    ev = await store.events_after(eid - 1, 10)
    assert ev[0]["type"] == "message" and ev[0]["payload"] == {"x": 1}


async def test_flows_by_issuer_chain(store: Store):
    await store.put_message(row(3, seq=3, prev=bid(2), ts=30))
    await store.put_message(row(1, seq=1, prev=None, ts=10))
    await store.put_message(row(2, seq=2, prev=bid(1), ts=20))
    await store.put_message(row(9, iss="did:other", seq=1, ts=5))
    chain = await store.flows("issuer", "did:a")
    assert [m["block_id"] for m in chain] == [bid(1), bid(2), bid(3)]
    assert [m["prev"] for m in chain] == [None, bid(1), bid(2)]
    summ = {s["key"]: s for s in await store.flows("issuer", None)}
    assert summ["did:a"]["count"] == 3 and summ["did:a"]["first_ts"] == 10
    assert summ["did:a"]["last_ts"] == 30 and summ["did:other"]["count"] == 1


async def test_flows_other_dimensions(store: Store):
    await store.put_message(row(1, corr="c1", json={"serviceComponentId": "svc"}))
    await store.put_message(row(2, corr="c1", json={"serviceComponentId": "svc"}))
    assert len(await store.flows("corr", "c1")) == 2
    assert len(await store.flows("service", "svc")) == 2
    assert (await store.flows("ie", None))[0]["count"] == 2
    with pytest.raises(ValueError):
        await store.flows("nope", None)  # type: ignore[arg-type]


async def test_lifecycle_updates_message_status(store: Store):
    await store.put_message(row(1, ms_index=None, wf_index=None))
    await store.set_lifecycle(block_id=bid(1), sub_id=None, status="SOLID", at_ms=10)
    await store.set_lifecycle(block_id=bid(1), sub_id=None, status="CONFIRMED", at_ms=20,
                              detail={"ms": 4})
    # a late, older event must not downgrade the status
    await store.set_lifecycle(block_id=bid(1), sub_id=None, status="SUBMITTED", at_ms=5)
    msg = await store.get_message(bid(1))
    assert msg["status"] == "CONFIRMED" and msg["confirmed_at_ms"] == 20
    assert [e["status"] for e in await store.lifecycle(bid(1))] == [
        "SUBMITTED", "SOLID", "CONFIRMED"]
    with pytest.raises(ValueError):
        await store.set_lifecycle(block_id=bid(1), sub_id=None, status="BOGUS", at_ms=1)


async def test_lifecycle_before_message_and_by_sub(store: Store):
    await store.put_submission(
        Submission(sub_id="s1", source="mqtt", received_at_ms=1, block_id=bid(4)))
    await store.set_lifecycle(block_id=None, sub_id="s1", status="RECEIVED", at_ms=1)
    await store.set_lifecycle(block_id=bid(4), sub_id=None, status="SOLID", at_ms=2)
    await store.put_message(row(4))
    assert (await store.get_message(bid(4)))["status"] == "SOLID"
    assert [e["status"] for e in await store.lifecycle(bid(4))] == ["RECEIVED", "SOLID"]


async def test_validations_and_content_checks(store: Store):
    await store.put_validation(bid(1), 5, True, 4, "included", False)
    await store.put_content_check(bid(1), 6, "MISMATCH", {"field": "tag"})
    with pytest.raises(psycopg.errors.CheckViolation):
        await store.put_content_check(bid(1), 7, "WRONG", None)
    st = await store.stats()
    assert st["validations"] == 1 and st["content_checks"] == 1


async def test_incidents(store: Store):
    iid = await store.put_incident(opened_at_ms=1, severity="high", title="t", ie_id="ie-a")
    await store.attach_incident_event(iid, bid(1), "trigger")
    await store.attach_incident_event(iid, bid(1), "trigger")
    await store.put_incident(opened_at_ms=2, severity="low", title="u", status="closed",
                             closed_at_ms=3)
    assert len(await store.incidents(None)) == 2
    assert [i["id"] for i in await store.incidents({"status": "open"})] == [iid]
    one = await store.incident(iid)
    assert one["title"] == "t" and one["events"] == [{"block_id": bid(1), "role": "trigger"}]
    assert await store.incident(999) is None


async def test_issuer_state_ignores_forged_and_excludes(store: Store):
    await store.put_message(row(1, seq=1, nonce="a", verdict="PRODUCER_SIGNED"))
    await store.put_message(row(2, seq=999999, nonce="evil", verdict="FORGED"))
    await store.put_message(row(3, seq=2, nonce="c", verdict="RELAY_ATTESTED"))
    assert await store.issuer_state("did:a") == (2, {"a", "c"})
    assert await store.issuer_state("did:a", exclude_block_id=bid(3)) == (1, {"a"})


async def test_confirmation_path(store: Store):
    first = row(1, ms_index=None, wf_index=None, ts=0, verdict=None, nonce=None, iat=None,
                received_at_ms=5000)
    assert await store.put_message(first) == "inserted"
    assert (await store.get_message(bid(1)))["confirmed_at_ms"] is None
    done = row(1, ms_index=8, wf_index=3, ts=1700, verdict="PRODUCER_SIGNED", nonce="n1", iat=42)
    assert await store.put_message(done) == "confirmed"
    assert await store.put_message(done) is None
    m = await store.get_message(bid(1))
    assert (m["ms_index"], m["wf_index"], m["ts"], m["verdict"], m["nonce"], m["iat"]) == (
        8, 3, 1700, "PRODUCER_SIGNED", "n1", 42)
    assert m["confirmed_at_ms"] == 1_700_000 and m["received_at_ms"] == 5000


async def test_date_filter_covers_indexer_only_rows(store: Store):
    # indexer-only row: ts is in seconds -> 10_000 ms; relay row received at 5_000 ms
    await store.put_message(row(1, ts=10, ms_index=1, wf_index=0, received_at_ms=None))
    await store.put_message(row(2, ts=0, ms_index=None, wf_index=None, received_at_ms=5000))

    async def ids(**kw):
        items, _ = await store.query_messages(MessageFilter(**kw), None, 10)
        return sorted(i["block_id"] for i in items)

    assert await ids(date_from_ms=8000) == [bid(1)]
    assert await ids(date_to_ms=8000) == [bid(2)]
    assert await ids(date_from_ms=0, date_to_ms=20000) == [bid(1), bid(2)]


async def test_alert_dedupe_key(store: Store):
    def mk(key):
        return Alert("STALE", "low", None, "ie-a", {}, 1, dedupe_key=key)

    assert await store.put_alert(mk("w1")) is True
    assert await store.put_alert(mk("w1")) is False
    assert await store.put_alert(mk("w2")) is True


async def test_anchors(store: Store):
    kw = {"ms_root": b"r", "checkpoint": {"a": 1}, "checkpoint_hash": b"h",
          "network": "iota-test", "created_at_ms": 1}
    assert await store.put_anchor(seq=1, from_ms=10, to_ms=19, **kw) is True
    assert await store.put_anchor(seq=1, from_ms=10, to_ms=19, **kw) is False
    await store.put_anchor(seq=2, from_ms=20, to_ms=29, **kw)
    assert (await store.anchor_covering(15))["seq"] == 1
    assert (await store.anchor_covering(20))["seq"] == 2
    assert await store.anchor_covering(30) is None
    assert await store.set_anchor_status(2, "anchored", tx="0xabc", record=7) is True
    assert await store.set_anchor_status(99, "failed") is False
    a = (await store.anchors(10))[0]
    assert (a["seq"], a["status"], a["tx"], a["record"]) == (2, "anchored", "0xabc", 7)
    with pytest.raises(psycopg.errors.CheckViolation):
        await store.set_anchor_status(1, "bogus")


async def test_lifecycle_requires_an_id(store: Store):
    with pytest.raises(ValueError):
        await store.set_lifecycle(block_id=None, sub_id=None, status="SOLID", at_ms=1)
    with pytest.raises(psycopg.errors.CheckViolation):
        async with store._conn() as c:
            await c.execute(
                "INSERT INTO lifecycle (status, at_ms) VALUES ('SOLID', 1)")


async def test_transaction_rolls_back_everything(store: Store):
    class Boom(Exception):
        pass

    with pytest.raises(Boom):
        async with store.transaction():
            await store.put_message(row(1))
            await store.emit("message", {})
            await store.set_cursor(77)
            await store.set_lifecycle(block_id=bid(1), sub_id=None, status="SOLID", at_ms=1)
            raise Boom
    st = await store.stats()
    assert (st["messages"], st["events"], st["lifecycle"], st["cursor"]) == (0, 0, 0, 0)
    async with store.transaction():
        await store.put_message(row(1))
        await store.emit("message", {})
        await store.set_cursor(77)
    st = await store.stats()
    assert (st["messages"], st["events"], st["cursor"]) == (1, 1, 77)


async def test_emit_ids_follow_commit_order(store: Store):
    a_in, release = asyncio.Event(), asyncio.Event()

    async def slow():
        async with store.transaction():
            await store.emit("a", {})
            a_in.set()
            await release.wait()

    ta = asyncio.create_task(slow())
    await a_in.wait()
    tb = asyncio.create_task(store.emit("b", {}))
    await asyncio.sleep(0.3)
    # B must wait for A: nothing is visible yet and B has not been allocated an id
    assert not tb.done()
    assert await store.events_after(0, 10) == []
    release.set()
    await ta
    await tb
    evs = await store.events_after(0, 10)
    assert [e["type"] for e in evs] == ["a", "b"]
    assert evs[0]["id"] < evs[1]["id"]


async def test_incident_events_ordered_by_time(store: Store):
    await store.put_message(row(1, ts=300))
    await store.put_message(row(2, ts=100))
    iid = await store.put_incident(opened_at_ms=1, severity="high", title="t")
    await store.attach_incident_event(iid, bid(1), "late")
    await store.attach_incident_event(iid, bid(2), "early")
    assert [e["role"] for e in (await store.incident(iid))["events"]] == ["early", "late"]


async def test_child_task_cannot_use_pinned_connection(store: Store):
    async with store.transaction():
        await store.put_message(row(1))
        with pytest.raises(RuntimeError, match="pinned to another task"):
            await asyncio.create_task(store.stats())
        with pytest.raises(RuntimeError):
            await asyncio.gather(store.stats())
    assert (await store.stats())["messages"] == 1


async def test_confirmation_keeps_stronger_values(store: Store):
    first = row(1, ms_index=None, wf_index=None, ts=0, verdict="RELAY_ATTESTED", nonce="n",
                iat=7, received_at_ms=100)
    await store.put_message(first)
    weak = row(1, ms_index=3, wf_index=0, ts=0, verdict=None, nonce=None, iat=None)
    assert await store.put_message(weak) == "confirmed"
    m = await store.get_message(bid(1))
    assert (m["verdict"], m["nonce"], m["iat"], m["ts"]) == ("RELAY_ATTESTED", "n", 7, 0)
    assert m["confirmed_at_ms"] is None and m["ms_index"] == 3
    await store.put_message(row(2, ms_index=None, wf_index=None, verdict="RELAY_ATTESTED"))
    forged = row(2, ms_index=4, wf_index=1, ts=50, verdict="FORGED")
    assert await store.put_message(forged) == "confirmed"
    m2 = await store.get_message(bid(2))
    assert m2["verdict"] == "FORGED" and m2["confirmed_at_ms"] == 50_000
