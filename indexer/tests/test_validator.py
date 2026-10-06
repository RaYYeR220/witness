import asyncio
import json
import os
import time
import uuid
from pathlib import Path

import httpx
import pytest
import respx
from witness_core.codec import serialize_tagged_block
from witness_core.ids import blake2b256
from witness_indexer.hornet_rest import HornetRest
from witness_indexer.ingest import handle_record
from witness_indexer.store import MessageRow
from witness_indexer.validator import Validator, ValidatorConfig, json_diff

BASE = "http://hornet.test"
PARENTS = [b"\x11" * 32, b"\x22" * 32]
MSG = {"score": 0.5, "id": "MyDomain:aabbccddeeff"}


class FakeTime:
    def __init__(self):
        self.t = 0.0
        self.sleeps = []

    def clock(self):
        return self.t

    async def sleep(self, s):
        self.sleeps.append(s)
        self.t += s


def make_block(message=MSG, tag="trust.score", nonce=0):
    data = json.dumps(message).encode()
    raw = serialize_tagged_block(PARENTS, tag.encode(), data, nonce=nonce)
    return raw, blake2b256(raw), data


def rec(sub_id, bid, data, tag="trust.score", **over):
    r = {
        "subId": sub_id,
        "receivedAtMs": 1_760_000_000_000,
        "tag": tag,
        "message": MSG,
        "dataHex": None if data is None else "0x" + data.hex(),
        "blockId": None if bid is None else "0x" + bid.hex(),
        "hornetStatus": 201,
        "relay": {"verdict": None, "iss": None, "seq": None},
    }
    r.update(over)
    return r


def meta(bid, solid=True, ms=None):
    m = {"blockId": "0x" + bid.hex(), "parents": ["0x" + p.hex() for p in PARENTS],
         "isSolid": solid, "shouldReattach": False}
    if ms is not None:
        m.update(referencedByMilestoneIndex=ms, ledgerInclusionState="noTransaction",
                 whiteFlagIndex=0)
    return m


def as_response(item):
    if isinstance(item, Exception):
        return item
    if isinstance(item, int):
        return httpx.Response(item, json={"error": {"code": str(item)}})
    return httpx.Response(200, json=item)


def serve(bid, raw, metas):
    """Mock HORNET for one block: metadata answers in order, then the raw block."""
    url = f"{BASE}/api/core/v2/blocks/0x{bid.hex()}"
    if callable(metas):
        meta_route = respx.get(url + "/metadata").mock(side_effect=metas)
    else:
        meta_route = respx.get(url + "/metadata").mock(
            side_effect=[as_response(m) for m in metas])
    block = httpx.Response(404) if raw is None else httpx.Response(200, content=raw)
    block_route = respx.get(url).mock(return_value=block)
    return meta_route, block_route


@pytest.fixture
async def env(store):
    clock = FakeTime()
    hornet = HornetRest(BASE)
    v = Validator(store, hornet, ValidatorConfig(reverify_batch=2),
                  sleep=clock.sleep, clock=clock.clock)
    try:
        yield store, v, clock
    finally:
        await v.stop()
        await hornet.close()


async def statuses(store, bid):
    return [r["status"] for r in await store.lifecycle(bid)]


@respx.mock
async def test_happy_path_lifecycle(env):
    store, v, clock = env
    raw, bid, data = make_block()
    _, block_route = serve(bid, raw, [meta(bid, solid=False), meta(bid), meta(bid, ms=42)])

    assert await handle_record(store, v, rec("s-1", bid, data), source="mqtt") is True
    assert await v.validate_once(bid, "s-1") == "CONTENT_VERIFIED"

    assert await statuses(store, bid) == [
        "RECEIVED", "SUBMITTED", "SOLID", "CONFIRMED", "CONTENT_VERIFIED"]
    life = await store.lifecycle(bid)
    assert life[3]["detail"]["referencedByMilestoneIndex"] == 42
    assert life[3]["detail"]["ledgerInclusionState"] == "noTransaction"

    vals = await store.validations(bid)
    assert [r["is_solid"] for r in vals] == [False, True, True]
    assert vals[-1]["referenced_by_ms"] == 42
    assert vals[-1]["ledger_inclusion_state"] == "noTransaction"
    assert vals[-1]["should_reattach"] is False

    checks = await store.content_checks(bid)
    assert [c["result"] for c in checks] == ["MATCH"]
    assert block_route.call_count == 1
    assert clock.sleeps == [0.5, 1.0]
    assert await store.alerts() == []

    events = await store.events_after(0, 50)
    assert [e["type"] for e in events] == ["submission", "lifecycle", "lifecycle", "lifecycle"]
    assert [e["payload"]["status"] for e in events[1:]] == [
        "SOLID", "CONFIRMED", "CONTENT_VERIFIED"]


@respx.mock
async def test_validate_again_does_not_repeat_transitions(env):
    store, v, _ = env
    raw, bid, data = make_block()
    serve(bid, raw, [meta(bid, ms=5), meta(bid, ms=5)])
    await handle_record(store, v, rec("s-1", bid, data), source="mqtt")
    assert await v.validate_once(bid, "s-1") == "CONTENT_VERIFIED"
    assert await v.validate_once(bid, "s-1") == "CONTENT_VERIFIED"
    assert await statuses(store, bid) == [
        "RECEIVED", "SUBMITTED", "SOLID", "CONFIRMED", "CONTENT_VERIFIED"]
    assert len(await store.content_checks(bid)) == 2


@respx.mock
async def test_solid_lag_retry_backoff(env):
    store, v, clock = env
    raw, bid, data = make_block()
    serve(bid, raw, [404, meta(bid, solid=False), httpx.ConnectError("node restarting"),
                     meta(bid, ms=7)])
    await handle_record(store, v, rec("s-1", bid, data), source="http")

    assert await v.validate_once(bid, "s-1") == "CONTENT_VERIFIED"
    assert clock.sleeps == [0.5, 1.0, 2.0]
    # Only answers that carried metadata are recorded.
    assert [r["is_solid"] for r in await store.validations(bid)] == [False, True]


@respx.mock
async def test_content_mismatch(env):
    store, v, _ = env
    raw, bid, data = make_block()
    forwarded = data.replace(b"0.5", b"0.6")
    assert len(forwarded) == len(data)
    serve(bid, raw, [meta(bid, ms=3)])
    await handle_record(store, v, rec("s-1", bid, forwarded), source="mqtt")

    assert await v.validate_once(bid, "s-1") == "CONTENT_MISMATCH"
    assert (await statuses(store, bid))[-1] == "CONTENT_MISMATCH"

    [alert] = await store.alerts()
    assert (alert["rule"], alert["severity"], alert["block_id"]) == (
        "CONTENT_MISMATCH", "critical", bid)
    diff = alert["evidence"]["diff"]
    [field] = diff["fields"]
    assert field["field"] == "data"
    assert field["expected"] == "0x" + forwarded.hex()
    assert field["actual"] == "0x" + data.hex()
    assert field["firstDiffOffset"] == data.index(b"0.5") + 2
    assert diff["json"]["equal"] is False
    assert diff["json"]["changes"] == [
        {"path": "$.score", "kind": "changed", "expected": 0.6, "actual": 0.5}]

    [check] = await store.content_checks(bid)
    assert check["result"] == "MISMATCH"
    assert check["diff"]["fields"][0]["field"] == "data"


@respx.mock
async def test_tag_mismatch(env):
    store, v, _ = env
    raw, bid, data = make_block(tag="trust.score")
    serve(bid, raw, [meta(bid, ms=3)])
    await handle_record(store, v, rec("s-1", bid, data, tag="trust.scorf"), source="mqtt")
    assert await v.validate_once(bid, "s-1") == "CONTENT_MISMATCH"
    [check] = await store.content_checks(bid)
    [field] = check["diff"]["fields"]
    assert field == {"field": "tag", "expected": "0x" + b"trust.scorf".hex(),
                     "actual": "0x" + b"trust.score".hex(), "firstDiffOffset": 10}
    assert check["diff"]["json"]["equal"] is True


@respx.mock
async def test_wrong_block_for_id(env):
    store, v, _ = env
    _, bid, data = make_block()
    other, other_id, _ = make_block(nonce=7)  # same tag and data, different block
    serve(bid, other, [meta(bid, ms=3)])
    await handle_record(store, v, rec("s-1", bid, data), source="mqtt")

    assert await v.validate_once(bid, "s-1") == "CONTENT_MISMATCH"
    [check] = await store.content_checks(bid)
    assert check["diff"]["fields"] == [
        {"field": "blockId", "expected": "0x" + bid.hex(), "actual": "0x" + other_id.hex()}]
    [alert] = await store.alerts()
    assert alert["rule"] == "CONTENT_MISMATCH"


@respx.mock
async def test_undecodable_block_is_mismatch(env):
    store, v, _ = env
    _, bid, data = make_block()
    serve(bid, b"\x02\x00", [meta(bid, ms=3)])
    await handle_record(store, v, rec("s-1", bid, data), source="mqtt")
    assert await v.validate_once(bid, "s-1") == "CONTENT_MISMATCH"
    [check] = await store.content_checks(bid)
    assert {f["field"] for f in check["diff"]["fields"]} == {"blockId", "block"}


@respx.mock
async def test_not_found_after_confirm(env):
    store, v, _ = env
    _, bid, data = make_block()
    serve(bid, None, [meta(bid, ms=3)])
    await handle_record(store, v, rec("s-1", bid, data), source="mqtt")

    assert await v.validate_once(bid, "s-1") == "NOT_FOUND"
    assert (await statuses(store, bid))[-1] == "NOT_FOUND"
    [check] = await store.content_checks(bid)
    assert check["result"] == "NOT_FOUND"
    [alert] = await store.alerts()
    assert (alert["rule"], alert["severity"]) == ("NOT_FOUND", "critical")


@respx.mock
async def test_orphan_timeout(env):
    store, v, clock = env
    raw, bid, data = make_block()
    _, block_route = serve(bid, raw, lambda request: httpx.Response(200, json=meta(bid)))
    await handle_record(store, v, rec("s-1", bid, data), source="mqtt")

    assert await v.validate_once(bid, "s-1") == "ORPHANED"
    assert await statuses(store, bid) == ["RECEIVED", "SUBMITTED", "SOLID", "ORPHANED"]
    assert clock.sleeps[:6] == [0.5, 1.0, 2.0, 4.0, 8.0, 8.0]
    assert max(clock.sleeps) == 8.0
    assert sum(clock.sleeps) == pytest.approx(60.0)
    assert not block_route.called

    [alert] = await store.alerts()
    assert (alert["rule"], alert["severity"], alert["block_id"]) == ("ORPHANED", "high", bid)
    assert alert["evidence"]["subId"] == "s-1"
    assert alert["evidence"]["lastMetadata"]["isSolid"] is True


async def test_failed_submit_not_polled(env):
    store, v, _ = env
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        anything = mock.route()
        record = rec("s-f", None, None, hornetStatus=502)
        assert await handle_record(store, v, record, source="mqtt") is True
        assert await v.validate_once(None, "s-f") == "RECEIVED"
        assert v.pending == 0
        assert not anything.called
    rows = await store._fetch("SELECT status FROM lifecycle WHERE sub_id = %s", ("s-f",))
    assert [r["status"] for r in rows] == ["RECEIVED"]


@respx.mock
async def test_worker_validates_enqueued_blocks(env):
    store, v, _ = env
    raw, bid, data = make_block()
    serve(bid, raw, [meta(bid, ms=3)])
    worker = asyncio.create_task(v.run())
    await handle_record(store, v, rec("s-1", bid, data), source="mqtt")
    for _ in range(200):
        if (await statuses(store, bid))[-1] == "CONTENT_VERIFIED":
            break
        await asyncio.sleep(0.05)
    assert (await statuses(store, bid))[-1] == "CONTENT_VERIFIED"
    await v.stop()
    await asyncio.wait_for(worker, 5)


@respx.mock
async def test_resume_requeues_unfinished(env):
    store, v, _ = env
    raw, done, data = make_block({"id": "done"})
    serve(done, raw, [meta(done, ms=3)])
    await handle_record(store, v, rec("s-done", done, data), source="mqtt")
    await v.validate_once(done, "s-done")
    _, cut, cut_data = make_block({"id": "cut"})
    await handle_record(store, v, rec("s-cut", cut, cut_data), source="mqtt")
    await handle_record(store, v, rec("s-failed", None, None, hornetStatus=400),
                        source="mqtt")

    fresh = Validator(store, v.hornet)  # a restarted indexer
    assert await fresh.resume() == 1
    assert fresh.pending == 1


@respx.mock
async def test_reverify_detects_db_tamper(env):
    store, v, _ = env
    blocks = {}
    for name in ("a", "b", "c"):
        raw, bid, data = make_block({"score": 0.5, "id": f"MyDomain:{name}"})
        serve(bid, raw, [meta(bid, ms=3)])
        await handle_record(store, v, rec(f"s-{name}", bid, data), source="mqtt")
        await store.put_message(MessageRow(block_id=bid, tag="trust.score", data=data))
        assert await v.validate_once(bid, f"s-{name}") == "CONTENT_VERIFIED"
        blocks[name] = (bid, data)

    a_bid, a_data = blocks["a"]
    c_bid, c_data = blocks["c"]
    forged = "0x" + a_data.replace(b"0.5", b"0.9").hex()
    await store._fetch("UPDATE submissions SET data_hex = %s WHERE block_id = %s RETURNING 1",
                       (forged, a_bid))
    await store._fetch("UPDATE messages SET data = %s WHERE block_id = %s RETURNING 1",
                       (c_data + b" ", c_bid))

    alerts = await v.reverify_all()
    assert sorted(a.block_id for a in alerts) == sorted([a_bid, c_bid])
    assert {(a.rule, a.severity) for a in alerts} == {("DB_TAMPER", "critical")}
    by_block = {a.block_id: a for a in alerts}
    assert by_block[a_bid].dedupe_key.startswith(a_bid.hex() + ":")
    assert [f["field"] for f in by_block[a_bid].evidence["fields"]] == ["submissions.data_hex"]
    assert [f["field"] for f in by_block[c_bid].evidence["fields"]] == ["messages.data"]

    assert (await statuses(store, a_bid))[-1] == "CONTENT_MISMATCH"
    assert (await store.lifecycle(a_bid))[-1]["detail"]["cause"] == "DB_TAMPER"
    assert (await statuses(store, blocks["b"][0]))[-1] == "CONTENT_VERIFIED"

    assert await v.reverify_all() == []
    assert len(await store.alerts({"rule": "DB_TAMPER"})) == 2


@respx.mock
async def test_reverify_respects_limit(env):
    store, v, _ = env
    for name in ("a", "b", "c"):
        raw, bid, data = make_block({"id": name})
        serve(bid, raw, [meta(bid, ms=3)])
        await handle_record(store, v, rec(f"s-{name}", bid, data), source="mqtt")
        await v.validate_once(bid, f"s-{name}")
    before = len(respx.calls)
    assert await v.reverify_all(limit=2) == []
    assert len(respx.calls) - before == 2


def test_json_diff_handles_any_json():
    assert json_diff(b'{"a": 1, "b": [1, 2]}', b'{"b":[1,2],"a":1}') == {
        "comparable": True, "equal": True, "changes": []}
    d = json_diff(b'{"a": 1, "b": [1, 2], "c": 0}', b'{"a": 2, "b": [1], "d": null}')
    assert d["equal"] is False
    assert d["changes"] == [
        {"path": "$.a", "kind": "changed", "expected": 1, "actual": 2},
        {"path": "$.b[1]", "kind": "removed", "expected": 2},
        {"path": "$.c", "kind": "removed", "expected": 0},
        {"path": "$.d", "kind": "added", "actual": None},
    ]
    assert json_diff(b"[1]", b'"x"')["changes"] == [
        {"path": "$", "kind": "changed", "expected": [1], "actual": "x"}]
    assert json_diff(b"7", b"7")["equal"] is True
    assert json_diff(b"not json", b"{}") == {"comparable": False}
    assert json_diff(b"[" * 5000, b"[]") == {"comparable": False}


def test_json_diff_caps_changes():
    many = json_diff(json.dumps(list(range(300))).encode(), b"[]")
    assert len(many["changes"]) == 200 and many["truncated"] is True
    exact = json_diff(json.dumps(list(range(200))).encode(), b"[]")
    assert len(exact["changes"]) == 200 and "truncated" not in exact


LIVE_RELAY = os.environ.get("WITNESS_LIVE_RELAY", "http://127.0.0.1:5556")
LIVE_HORNET = os.environ.get("WITNESS_LIVE_HORNET", "http://127.0.0.1:14265")
VECTORS = Path(__file__).resolve().parents[2] / "core" / "tests" / "vectors"
needs_stack = pytest.mark.skipif(os.environ.get("WITNESS_LIVE") != "1",
                                 reason="set WITNESS_LIVE=1")


async def _require_fresh_milestones():
    async with httpx.AsyncClient(timeout=10) as http:
        info = (await http.get(f"{LIVE_HORNET}/api/core/v2/info")).json()
    age = time.time() - info["status"]["confirmedMilestone"]["timestamp"]
    if age > 60:
        pytest.fail(f"HORNET confirmed no milestone for {age:.0f} s; is the coordinator up?")


@pytest.mark.live
@needs_stack
async def test_live_validate(store):
    await _require_fresh_milestones()
    tag = "witness.validator.live"
    message = {"probe": uuid.uuid4().hex, "score": 0.75}
    async with httpx.AsyncClient(timeout=30) as http:
        r = await http.post(f"{LIVE_RELAY}/upload?node=iota-hornet",
                            json={"tag": tag, "message": message})
    r.raise_for_status()
    body = r.json()
    block_hex = json.loads(body["return_payload"])["blockId"]
    # The stock Messages API submits json.dumps(message) as the tagged-data bytes.
    data = json.dumps(message).encode()
    record = rec(f"live-{uuid.uuid4().hex[:8]}", bytes.fromhex(block_hex[2:]), data, tag=tag,
                 message=message, hornetStatus=body["status_code"])

    hornet = HornetRest(LIVE_HORNET)
    v = Validator(store, hornet, ValidatorConfig(timeout_s=90))
    try:
        assert await handle_record(store, v, record, source="http")
        bid = bytes.fromhex(block_hex[2:])
        assert await v.validate_once(bid, record["subId"]) == "CONTENT_VERIFIED"
        assert await statuses(store, bid) == [
            "RECEIVED", "SUBMITTED", "SOLID", "CONFIRMED", "CONTENT_VERIFIED"]
        assert [c["result"] for c in await store.content_checks(bid)] == ["MATCH"]
        assert await v.reverify_all() == []
    finally:
        await v.stop()
        await hornet.close()


@pytest.mark.live
@needs_stack
async def test_live_validate_recorded_upload(store):
    """Checks (c) and (d) against the real node for the upload captured when the stack was
    first started; works even while no new milestones are being issued."""
    vec = json.loads((VECTORS / "legacy_upload_response.json").read_text())
    request = vec["request"]
    block_hex = json.loads(json.loads(vec["bodyUtf8"])["return_payload"])["blockId"]
    bid = bytes.fromhex(block_hex[2:])
    data = json.dumps(request["message"]).encode()

    hornet = HornetRest(LIVE_HORNET)
    v = Validator(store, hornet, ValidatorConfig(timeout_s=10))
    try:
        record = rec("vector-ok", bid, data, tag=request["tag"], message=request["message"])
        assert await handle_record(store, v, record, source="http")
        assert await v.validate_once(bid, "vector-ok") == "CONTENT_VERIFIED"
        assert await statuses(store, bid) == [
            "RECEIVED", "SUBMITTED", "SOLID", "CONFIRMED", "CONTENT_VERIFIED"]
        [val] = await store.validations(bid)
        assert val["is_solid"] is True and val["referenced_by_ms"] > 0

        # The same block claimed with one byte changed must not verify.
        await store._fetch("UPDATE submissions SET data_hex = %s WHERE sub_id = %s RETURNING 1",
                           ("0x" + data.replace(b"0.5", b"0.6").hex(), "vector-ok"))
        assert await v.validate_once(bid, "vector-ok") == "CONTENT_MISMATCH"
        [alert] = await store.alerts({"rule": "CONTENT_MISMATCH"})
        assert alert["evidence"]["diff"]["json"]["changes"][0]["path"] == "$.score"
    finally:
        await v.stop()
        await hornet.close()
