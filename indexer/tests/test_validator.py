import asyncio
import json
import os
import re
import time
import uuid
from pathlib import Path

import httpx
import pytest
import respx
from witness_core.codec import serialize_tagged_block
from witness_core.ids import blake2b256
from witness_indexer.hornet_rest import RAW_MEDIA_TYPE, HornetRest
from witness_indexer.ingest import handle_record
from witness_indexer.store import Alert, MessageRow
from witness_indexer.validator import PassResult, Validator, ValidatorConfig, json_diff

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
    if isinstance(item, httpx.Response):
        return item
    if isinstance(item, Exception):
        return item
    if isinstance(item, int):
        return httpx.Response(item, json={"error": {"code": str(item)}})
    return httpx.Response(200, json=item)


def binary(raw):
    return httpx.Response(200, content=raw, headers={"Content-Type": RAW_MEDIA_TYPE})


def serve(bid, raw, metas):
    """Mock HORNET for one block: metadata answers in order, then the raw block."""
    url = f"{BASE}/api/core/v2/blocks/0x{bid.hex()}"
    name = f"meta-{bid.hex()}"
    if callable(metas):
        meta_route = respx.get(url + "/metadata", name=name).mock(side_effect=metas)
    else:
        meta_route = respx.get(url + "/metadata", name=name).mock(
            side_effect=[as_response(m) for m in metas])
    block = httpx.Response(404) if raw is None else binary(raw)
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
    assert len(await store.content_checks(bid)) == 1  # an unchanged result is not repeated


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


UNAVAILABLE = httpx.Response(503, text="node restarting")


def answers(bid, pattern):
    """Metadata answers by poll number for one 60 s window (12 polls with the defaults):
    "503" unreachable, "404" unknown block, "meta" known but not referenced."""
    calls = {"n": 0}

    def answer(request):
        kind = pattern[min(calls["n"], len(pattern) - 1)]
        calls["n"] += 1
        if kind == "503":
            return httpx.Response(503, text="node restarting")
        if kind == "404":
            return httpx.Response(404, json={"error": {}})
        return httpx.Response(200, json=meta(bid, solid=False))

    return answer


@respx.mock
@pytest.mark.parametrize(("pattern", "expected"), [
    (["503"] * 12, "SUBMITTED"),                   # never answered
    (["meta"] * 11 + ["503"], "SUBMITTED"),        # unreachable at the deadline
    (["503"] * 11 + ["404"], "SUBMITTED"),         # only the last poll answered
    (["404"] + ["503"] * 10 + ["404"], "ORPHANED"),
    (["404"] * 12, "ORPHANED"),                    # the node never heard of the block
], ids=["all-503", "last-503", "only-last-404", "first-and-last-404", "all-404"])
async def test_orphan_needs_definitive_answers(env, pattern, expected):
    store, v, _ = env
    raw, bid, data = make_block()
    meta_route, block_route = serve(bid, raw, answers(bid, pattern))
    await handle_record(store, v, rec("s-1", bid, data), source="mqtt")

    assert await v.validate_once(bid, "s-1") == expected
    assert meta_route.call_count == 12
    assert not block_route.called
    alerts = await store.alerts()
    if expected == "ORPHANED":
        assert await statuses(store, bid) == ["RECEIVED", "SUBMITTED", "ORPHANED"]
        assert [a["rule"] for a in alerts] == ["ORPHANED"]
        assert alerts[0]["evidence"]["answeredPolls"] == pattern.count("404")
    else:
        assert await statuses(store, bid) == ["RECEIVED", "SUBMITTED"]
        assert alerts == []


@respx.mock
@pytest.mark.parametrize("answer", [
    UNAVAILABLE,
    httpx.Response(200, json={"protocolVersion": 2}),  # Accept ignored
    httpx.Response(200, text="<html>maintenance</html>"),  # proxy page
], ids=["503", "json", "html"])
async def test_raw_fetch_unavailable_leaves_confirmed(env, answer):
    store, v, _ = env
    raw, bid, data = make_block()
    _, block_route = serve(bid, raw, [meta(bid, ms=3)])
    block_route.mock(return_value=answer)
    await handle_record(store, v, rec("s-1", bid, data), source="mqtt")

    assert await v.validate_once(bid, "s-1") == "CONFIRMED"
    assert (await statuses(store, bid))[-1] == "CONFIRMED"
    assert await store.content_checks(bid) == []
    assert await store.alerts() == []
    assert block_route.call_count > 1  # retried within the window


@respx.mock
async def test_direct_call_cannot_race_worker(env):
    store, v, _ = env
    raw, bid, data = make_block()
    serve(bid, raw, [meta(bid, ms=3), meta(bid, ms=3)])
    await handle_record(store, v, rec("s-1", bid, data), source="mqtt")
    results = await asyncio.gather(v.validate_once(bid, "s-1"), v.validate_once(bid, None))
    assert results == ["CONTENT_VERIFIED", "CONTENT_VERIFIED"]
    assert await statuses(store, bid) == [
        "RECEIVED", "SUBMITTED", "SOLID", "CONFIRMED", "CONTENT_VERIFIED"]


class SlowHornet(HornetRest):
    """Answers like the node, but slowly, and records how many validations overlap."""

    def __init__(self, base_url, overlap):
        super().__init__(base_url)
        self.overlap = overlap

    async def block_metadata(self, block_id):
        self.overlap["now"] += 1
        self.overlap["max"] = max(self.overlap["max"], self.overlap["now"])
        try:
            await asyncio.sleep(0.2)
            return await super().block_metadata(block_id)
        finally:
            self.overlap["now"] -= 1


@respx.mock
async def test_validators_in_two_processes_are_serialised(store):
    """The indexer's worker and the API's on-demand check share only the database: two
    validators (no shared in-process lock) validating one block take turns, and the
    lifecycle gets each status once."""
    raw, bid, data = make_block()
    serve(bid, raw, lambda request: httpx.Response(200, json=meta(bid, ms=7)))
    await handle_record(store, RecordingValidator(), rec("s-1", bid, data), source="mqtt")
    overlap = {"now": 0, "max": 0}
    first, second = SlowHornet(BASE, overlap), SlowHornet(BASE, overlap)
    try:
        results = await asyncio.gather(Validator(store, first).validate_once(bid, "s-1"),
                                       Validator(store, second).validate_once(bid, None))
    finally:
        await first.close()
        await second.close()
    assert results == ["CONTENT_VERIFIED", "CONTENT_VERIFIED"]
    assert overlap["max"] == 1
    assert await statuses(store, bid) == [
        "RECEIVED", "SUBMITTED", "SOLID", "CONFIRMED", "CONTENT_VERIFIED"]
    assert [c["result"] for c in await store.content_checks(bid)] == ["MATCH"]


async def eventually(check, timeout_s=15.0):
    for _ in range(int(timeout_s / 0.05)):
        if await check():
            return True
        await asyncio.sleep(0.05)
    return False


def quick_retry_validator(store, hornet, clock, **cfg):
    return Validator(store, hornet,
                     ValidatorConfig(retry_initial_s=0.01, retry_max_s=0.05, **cfg),
                     sleep=clock.sleep, clock=clock.clock)


@respx.mock
async def test_worker_requeues_unconcluded_validation(env):
    store, v, clock = env
    raw, bid, data = make_block()
    # A whole window unreachable, then the node is back and the block confirmed.
    meta_route, _ = serve(bid, raw, [503] * 12 + [meta(bid, ms=9)])
    worker_v = quick_retry_validator(store, v.hornet, clock, resume_every_s=3600)
    worker = asyncio.create_task(worker_v.run())
    try:
        await handle_record(store, worker_v, rec("s-1", bid, data), source="mqtt")

        async def verified():
            return (await statuses(store, bid))[-1] == "CONTENT_VERIFIED"

        assert await eventually(verified)
        assert meta_route.call_count == 13
        assert "ORPHANED" not in await statuses(store, bid)
        assert await store.alerts() == []

        async def settled():
            return worker_v.pending == 0

        assert await eventually(settled)
    finally:
        await worker_v.stop()
        await asyncio.wait_for(worker, 5)


@respx.mock
async def test_worker_retries_after_an_error(env):
    store, v, clock = env
    raw, bid, data = make_block()
    serve(bid, raw, [RuntimeError("bug in a dependency"), meta(bid, ms=9)])
    worker_v = quick_retry_validator(store, v.hornet, clock, resume_every_s=3600)
    worker = asyncio.create_task(worker_v.run())
    try:
        await handle_record(store, worker_v, rec("s-1", bid, data), source="mqtt")

        async def verified():
            return (await statuses(store, bid))[-1] == "CONTENT_VERIFIED"

        assert await eventually(verified)
    finally:
        await worker_v.stop()
        await asyncio.wait_for(worker, 5)


@respx.mock
async def test_periodic_resume_picks_up_unfinished(env):
    store, v, clock = env
    raw, bid, data = make_block()
    serve(bid, raw, [meta(bid, ms=9)])
    worker_v = quick_retry_validator(store, v.hornet, clock, resume_every_s=0.05)
    worker = asyncio.create_task(worker_v.run())
    try:
        # Stored by another process (or before a crash): never enqueued on this validator.
        await handle_record(store, RecordingValidator(), rec("s-1", bid, data), source="http")

        async def verified():
            return (await statuses(store, bid))[-1] == "CONTENT_VERIFIED"

        assert await eventually(verified)
    finally:
        await worker_v.stop()
        await asyncio.wait_for(worker, 5)


class RecordingValidator:
    def __init__(self):
        self.enqueued = []

    def enqueue(self, block_id, sub_id):
        self.enqueued.append((block_id, sub_id))


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
        await handle_record(store, RecordingValidator(), rec(f"s-{name}", bid, data),
                            source="mqtt")
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


async def verified_block(store, v, name, *, with_message=True):
    raw, bid, data = make_block({"score": 0.5, "id": f"MyDomain:{name}"})
    _, block_route = serve(bid, raw, [meta(bid, ms=3)])
    # Validated directly below, so not left queued (in flight) on `v`.
    await handle_record(store, RecordingValidator(), rec(f"s-{name}", bid, data), source="mqtt")
    if with_message:
        await store.put_message(MessageRow(block_id=bid, tag="trust.score", data=data))
    assert await v.validate_once(bid, f"s-{name}") == "CONTENT_VERIFIED"
    return bid, data, block_route


async def tamper_submission(store, bid, data_hex):
    await store._fetch("UPDATE submissions SET data_hex = %s WHERE block_id = %s RETURNING 1",
                       (data_hex, bid))


@respx.mock
async def test_reverify_flags_consistent_edit_of_both_copies(env):
    store, v, _ = env
    bid, data, _ = await verified_block(store, v, "a")
    forged = data.replace(b"0.5", b"0.9")
    await tamper_submission(store, bid, "0x" + forged.hex())
    await store._fetch("UPDATE messages SET data = %s WHERE block_id = %s RETURNING 1",
                       (forged, bid))
    [alert] = await v.reverify_all()
    assert alert.rule == "DB_TAMPER"
    assert [f["field"] for f in alert.evidence["fields"]] == [
        "submissions.data_hex", "messages.data"]


@respx.mock
async def test_reverify_flags_nulled_message_copy(env):
    store, v, _ = env
    bid, _, _ = await verified_block(store, v, "a")
    await store._fetch("UPDATE messages SET tag = NULL, data = NULL WHERE block_id = %s "
                       "RETURNING 1", (bid,))
    [alert] = await v.reverify_all()
    assert [(f["field"], f["actual"]) for f in alert.evidence["fields"]] == [
        ("messages.tag", None), ("messages.data", None)]


@respx.mock
async def test_reverify_rechecks_blocks_already_flagged(env):
    store, v, _ = env
    bid, data, _ = await verified_block(store, v, "a")
    await tamper_submission(store, bid, "0x" + data.replace(b"0.5", b"0.9").hex())
    [first] = await v.reverify_all()
    assert (await statuses(store, bid))[-1] == "CONTENT_MISMATCH"
    assert await v.reverify_all() == []  # same tampering, already reported
    await tamper_submission(store, bid, "0x" + data.replace(b"0.5", b"0.1").hex())
    [second] = await v.reverify_all()  # the block is still re-verified after its first alert
    assert second.dedupe_key != first.dedupe_key
    assert len(await store.alerts({"rule": "DB_TAMPER"})) == 2


@respx.mock
@pytest.mark.parametrize("answer", ["404", "other-block", "503", "html"])
async def test_reverify_does_not_judge_without_the_block(env, answer):
    store, v, _ = env
    bid, data, block_route = await verified_block(store, v, "a")
    await tamper_submission(store, bid, "0x" + data.replace(b"0.5", b"0.9").hex())
    other, _, _ = make_block({"id": "someone else"})
    block_route.mock(return_value={
        "404": httpx.Response(404),
        "other-block": binary(other),
        "503": UNAVAILABLE,
        "html": httpx.Response(200, text="<html>"),
    }[answer])
    assert await v.reverify_all() == []
    assert await store.alerts() == []
    assert (await statuses(store, bid))[-1] == "CONTENT_VERIFIED"


@respx.mock
async def test_reverify_stops_when_node_goes_away_mid_pass(env):
    store, v, _ = env
    blocks = sorted([await verified_block(store, v, n) for n in ("a", "b", "c")])
    for bid, data, _ in blocks:
        await tamper_submission(store, bid, "0x" + data.replace(b"0.5", b"0.9").hex())
    blocks[1][2].mock(return_value=UNAVAILABLE)
    calls_before = blocks[2][2].call_count
    found = await v.reverify_all()
    assert [a.block_id for a in found] == [blocks[0][0]]
    assert blocks[2][2].call_count == calls_before  # not reached


async def delete_rows(store, table, bid, extra=""):
    await store._fetch(f"DELETE FROM {table} WHERE block_id = %s {extra} RETURNING 1", (bid,))


def node_says_confirmed(bid):
    respx.routes[f"meta-{bid.hex()}"].mock(
        return_value=httpx.Response(200, json=meta(bid, ms=3)))


@respx.mock
async def test_reverify_detects_removed_content(env):
    store, v, _ = env
    bid, data, _ = await verified_block(store, v, "a")
    await delete_rows(store, "submissions", bid)
    await delete_rows(store, "messages", bid)
    [alert] = await v.reverify_all()
    assert (alert.rule, alert.severity) == ("DB_TAMPER", "critical")
    assert alert.evidence["reason"] == "content removed"
    assert alert.evidence["fields"] == [
        {"field": "content", "expected": "0x" + data.hex(), "actual": None}]
    assert (await store.lifecycle(bid))[-1]["detail"]["reason"] == "content removed"


@respx.mock
async def test_reverify_survives_deleted_match_checks(env):
    store, v, _ = env
    bid, data, _ = await verified_block(store, v, "a")
    await delete_rows(store, "content_checks", bid)  # the lifecycle still says verified
    await tamper_submission(store, bid, "0x" + data.replace(b"0.5", b"0.9").hex())
    [alert] = await v.reverify_all()
    assert alert.rule == "DB_TAMPER"


@respx.mock
async def test_reverify_survives_wiped_validation_history(env):
    store, v, _ = env
    bid, data, _ = await verified_block(store, v, "a", with_message=False)
    await delete_rows(store, "content_checks", bid)
    await delete_rows(store, "lifecycle", bid)
    await tamper_submission(store, bid, "0x" + data.replace(b"0.5", b"0.9").hex())
    node_says_confirmed(bid)  # never verified as far as the DB shows: confirmation first
    [alert] = await v.reverify_all()
    assert alert.rule == "DB_TAMPER"
    assert [f["field"] for f in alert.evidence["fields"]] == ["submissions.data_hex"]


@respx.mock
async def test_partly_wiped_history_is_still_judged(env):
    store, v, _ = env
    bid, data, _ = await verified_block(store, v, "a", with_message=False)
    await delete_rows(store, "content_checks", bid)
    await delete_rows(store, "lifecycle", bid, "AND status = 'CONTENT_VERIFIED'")
    await tamper_submission(store, bid, "0x" + data.replace(b"0.5", b"0.9").hex())
    node_says_confirmed(bid)  # latest status now CONFIRMED, but nothing is in flight
    [alert] = await v.reverify_all()
    assert alert.rule == "DB_TAMPER"


@respx.mock
async def test_forged_verdict_rows_do_not_exempt_a_block(env):
    store, v, _ = env
    bid, data, _ = await verified_block(store, v, "a")
    await delete_rows(store, "content_checks", bid)
    await delete_rows(store, "lifecycle", bid, "AND status = 'CONTENT_VERIFIED'")
    # Forged: a terminal "verdict" and a failed check, as if the block were settled.
    await store.set_lifecycle(block_id=bid, sub_id="s-a", status="ORPHANED",
                              at_ms=4_000_000_000_000)
    await store.put_content_check(bid, 4_000_000_000_000, "MISMATCH", {"forged": True})
    await tamper_submission(store, bid, "0x" + data.replace(b"0.5", b"0.9").hex())
    node_says_confirmed(bid)
    [alert] = await v.reverify_all()
    assert alert.rule == "DB_TAMPER"
    assert [f["field"] for f in alert.evidence["fields"]] == ["submissions.data_hex"]


def confirmed_always(bid):
    return lambda request: httpx.Response(200, json=meta(bid, ms=3))


@respx.mock
async def test_reverify_skips_only_blocks_in_flight(env):
    store, v, _ = env
    # In flight: queued on `v`; its forwarded bytes differ from the Tangle.
    raw_p, pending, data_p = make_block({"id": "pending"})
    p_meta, p_block = serve(pending, raw_p, confirmed_always(pending))
    await handle_record(store, v, rec("s-p", pending, data_p.replace(b"pending", b"PENDING")),
                        source="mqtt")
    assert v.is_in_flight(pending)
    # Verified and done, then tampered with: not in flight, so judged.
    bid, data, _ = await verified_block(store, v, "done")
    await tamper_submission(store, bid, "0x" + data.replace(b"0.5", b"0.9").hex())
    assert not v.is_in_flight(bid)
    # Indexed but not (yet) confirmed according to the node.
    raw_u, unconf, data_u = make_block({"id": "unconfirmed"})
    serve(unconf, raw_u, lambda request: httpx.Response(200, json=meta(unconf, solid=True)))
    await store.put_message(MessageRow(block_id=unconf, tag="trust.score", data=data_u + b" "))

    before = (p_meta.call_count, p_block.call_count)
    [alert] = await v.reverify_all()
    assert (alert.rule, alert.block_id) == ("DB_TAMPER", bid)
    assert (p_meta.call_count, p_block.call_count) == before  # in flight: not touched

    # Once nothing has it in flight (here: a validator in another process), it is judged.
    other = Validator(store, v.hornet)
    [alert] = await other.reverify_all()
    assert (alert.rule, alert.block_id) == ("DB_TAMPER", pending)
    assert sorted(a["rule"] for a in await store.alerts()) == ["DB_TAMPER", "DB_TAMPER"]


FUTURE_MS = 4_000_000_000_000


def count_attempts(validator):
    """Record the block id of every validation attempt (each starts by reading the stored
    content)."""
    seen = []
    real = validator._expected

    async def spy(block_id, sub_id):
        seen.append(block_id)
        return await real(block_id, sub_id)

    validator._expected = spy
    return seen


async def reverify_after_resumed_attempts(store, v, clock, bid):
    """Forge an unfinished validation (a SUBMITTED row dated in the future) so resume() queues
    the block on every pass, let the worker try it twice (the start-up resume, then one more),
    and re-verify with that same worker's validator."""
    await store.set_lifecycle(block_id=bid, sub_id="s-a", status="SUBMITTED", at_ms=FUTURE_MS)
    worker_v = quick_retry_validator(store, v.hornet, clock, resume_every_s=3600)
    seen = count_attempts(worker_v)
    worker = asyncio.create_task(worker_v.run())
    try:
        async def dropped_after(n):
            return len(seen) == n and worker_v.pending == 0

        assert await eventually(lambda: dropped_after(1))  # given up, not retried
        assert await worker_v.resume() == 1
        assert await eventually(lambda: dropped_after(2))
        assert not worker_v.is_in_flight(bid)
        return await worker_v.reverify_all()
    finally:
        await worker_v.stop()
        await asyncio.wait_for(worker, 5)


@respx.mock
async def test_removed_content_cannot_keep_a_block_in_flight(env):
    store, v, clock = env
    bid, data, _ = await verified_block(store, v, "a")
    await store._fetch("UPDATE submissions SET tag = NULL, data_hex = NULL WHERE block_id = %s "
                       "RETURNING 1", (bid,))
    await store._fetch("UPDATE messages SET tag = NULL, data = NULL WHERE block_id = %s "
                       "RETURNING 1", (bid,))
    [alert] = await reverify_after_resumed_attempts(store, v, clock, bid)
    assert (alert.rule, alert.severity, alert.block_id) == ("DB_TAMPER", "critical", bid)
    assert alert.evidence["reason"] == "content removed"
    assert alert.evidence["fields"] == [
        {"field": "content", "expected": "0x" + data.hex(), "actual": None}]


@respx.mock
async def test_unparsable_stored_data_cannot_keep_a_block_in_flight(env):
    store, v, clock = env
    bid, data, _ = await verified_block(store, v, "a")
    await tamper_submission(store, bid, "zz")
    [alert] = await reverify_after_resumed_attempts(store, v, clock, bid)
    assert (alert.rule, alert.severity, alert.block_id) == ("DB_TAMPER", "critical", bid)
    assert alert.evidence["fields"] == [
        {"field": "submissions.data_hex", "expected": "0x" + data.hex(), "actual": "zz"}]


@respx.mock
async def test_reverify_skips_a_block_on_its_first_attempt(env):
    store, v, _ = env
    raw, bid, data = make_block({"id": "fresh"})
    meta_route, block_route = serve(bid, raw, confirmed_always(bid))
    # Its forwarded bytes differ from the Tangle: judged now, this would be DB_TAMPER.
    await handle_record(store, v, rec("s-f", bid, data.replace(b"fresh", b"FRESH")),
                        source="mqtt")
    assert v.is_in_flight(bid)  # queued for its first attempt
    assert await v.reverify_all() == []
    assert not meta_route.called and not block_route.called
    assert await store.alerts() == []


@respx.mock
@pytest.mark.parametrize("stored", ["same", "altered"])
async def test_reverify_judges_a_block_waiting_to_retry(env, stored):
    store, v, clock = env
    raw, bid, data = make_block({"id": "retrying"})
    # The first attempt finds the node unreachable for its whole window; then it is back.
    meta_route, block_route = serve(bid, raw, [503] * 12 + [meta(bid, ms=3)])
    worker_v = Validator(store, v.hornet,
                         ValidatorConfig(retry_initial_s=3600, retry_max_s=3600,
                                         resume_every_s=3600),
                         sleep=clock.sleep, clock=clock.clock)
    worker = asyncio.create_task(worker_v.run())
    try:
        await handle_record(store, worker_v, rec("s-r", bid, data), source="mqtt")

        async def retry_scheduled():
            return bid in worker_v._attempts

        assert await eventually(retry_scheduled)
        assert meta_route.call_count == 12
        assert worker_v.pending == 1
        assert not worker_v.is_in_flight(bid)
        if stored == "altered":
            await tamper_submission(store, bid,
                                    "0x" + data.replace(b"retrying", b"RETRYING").hex())

        alerts = await worker_v.reverify_all()
        assert (meta_route.call_count, block_route.call_count) == (13, 1)  # judged
        if stored == "same":
            assert alerts == []
            assert await store.alerts() == []
            assert await statuses(store, bid) == ["RECEIVED", "SUBMITTED"]
        else:
            [alert] = alerts
            assert alert.rule == "DB_TAMPER"
            assert [f["field"] for f in alert.evidence["fields"]] == ["submissions.data_hex"]
        assert worker_v.pending == 1  # its retry is still due
    finally:
        await worker_v.stop()
        await asyncio.wait_for(worker, 5)


@respx.mock
async def test_reverify_judges_confirmed_indexed_message(env):
    store, v, _ = env
    raw, bid, data = make_block({"id": "indexed"})
    serve(bid, raw, lambda request: httpx.Response(200, json=meta(bid, ms=3)))
    await store.put_message(MessageRow(block_id=bid, tag="trust.score", data=data + b" "))
    [alert] = await v.reverify_all()
    assert [f["field"] for f in alert.evidence["fields"]] == ["messages.data"]


@respx.mock
async def test_reverify_does_not_repeat_unchanged_findings(env):
    store, v, _ = env
    bid, data, _ = await verified_block(store, v, "a")
    await tamper_submission(store, bid, "0x" + data.replace(b"0.5", b"0.9").hex())
    assert len(await v.reverify_all()) == 1
    rows = len(await store.content_checks(bid))
    assert await v.reverify_all() == []
    assert await v.reverify_all() == []
    assert len(await store.content_checks(bid)) == rows
    await tamper_submission(store, bid, "0x" + data.replace(b"0.5", b"0.1").hex())
    assert len(await v.reverify_all()) == 1
    assert len(await store.content_checks(bid)) == rows + 1


@respx.mock
async def test_reverify_respects_limit(env):
    store, v, _ = env
    for name in ("a", "b", "c"):
        raw, bid, data = make_block({"id": name})
        serve(bid, raw, [meta(bid, ms=3)])
        await handle_record(store, RecordingValidator(), rec(f"s-{name}", bid, data),
                            source="mqtt")
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
    # Past the shared cap (2501 levels parse with json.loads on every platform).
    assert json_diff(b"[" * 2501 + b"]" * 2501, b"[]") == {"comparable": False}
    assert json_diff(b"[" * 2500 + b"]" * 2500, b"[]")["comparable"] is True


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
        assert await handle_record(store, RecordingValidator(), record, source="http")
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
    first started; works even while no new milestones are being issued. Skipped on a Tangle
    that was recreated since the capture, where that block does not exist."""
    vec = json.loads((VECTORS / "legacy_upload_response.json").read_text())
    request = vec["request"]
    block_hex = json.loads(json.loads(vec["bodyUtf8"])["return_payload"])["blockId"]
    bid = bytes.fromhex(block_hex[2:])
    data = json.dumps(request["message"]).encode()

    hornet = HornetRest(LIVE_HORNET)
    v = Validator(store, hornet, ValidatorConfig(timeout_s=10))
    try:
        if await hornet.block_metadata(bid) is None:
            pytest.skip(f"captured block {block_hex[:18]}... is not on this Tangle (recreated "
                        "since the vectors were captured)")
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


# -- scheduled re-verification ---------------------------------------------------------------


def tamper_sql(bid):
    """What the eval's A19 injection runs: flip the low bit of the first stored byte."""
    sql = ("UPDATE messages SET data = set_byte(data, 0, get_byte(data, 0) # 1) "
           "WHERE block_id = %s RETURNING 1")
    return sql, (bid,)


@respx.mock
async def test_scheduled_pass_catches_a_db_update(env):
    store, v, _ = env
    blocks = sorted([await verified_block(store, v, n) for n in ("a", "b", "c")])
    first = await v.scheduled_reverify()
    assert (first.checked, first.alerts, first.complete) == (3, [], True)
    status = (await store.service_status())["reverify"]
    assert status["status"] == "ok"
    assert re.fullmatch(r"last pass at \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ: 3 blocks, "
                        r"0 new DB_TAMPER", status["detail"])

    victim = blocks[1][0]
    await store._fetch(*tamper_sql(victim))
    second = await v.scheduled_reverify()
    [alert] = second.alerts
    assert (alert.rule, alert.severity, alert.block_id) == ("DB_TAMPER", "critical", victim)
    assert [f["field"] for f in alert.evidence["fields"]] == ["messages.data"]
    assert (await store.service_status())["reverify"]["detail"].endswith(
        ": 3 blocks, 1 new DB_TAMPER")
    # Deduplicated as before: the same tampering is reported once, however many passes.
    assert (await v.scheduled_reverify()).alerts == []
    assert len(await store.alerts({"rule": "DB_TAMPER"})) == 1


@respx.mock
async def test_scheduled_pass_asks_the_node_only_for_what_changed(env):
    store, v, _ = env
    blocks = sorted([await verified_block(store, v, n) for n in ("a", "b", "c")])
    await v.reverify_pass()  # fetches each block once and keeps its Tangle content
    routes = [route for _, _, route in blocks]
    before = [r.call_count for r in routes]
    assert (await v.reverify_pass()).checked == 3
    assert [r.call_count for r in routes] == before  # unchanged copies: no node traffic

    await tamper_submission(store, blocks[2][0], "0x" + blocks[2][1].replace(
        b"0.5", b"0.9").hex())
    [alert] = (await v.reverify_pass()).alerts
    assert alert.block_id == blocks[2][0]
    assert [r.call_count - b for r, b in zip(routes, before, strict=True)] == [0, 0, 1]


@respx.mock
async def test_scheduled_pass_resumes_where_the_node_cut_it_short(env):
    store, v, _ = env
    v.cfg = ValidatorConfig(reverify_batch=2, tangle_cache_size=0)  # always ask the node
    blocks = sorted([await verified_block(store, v, n) for n in ("a", "b", "c", "d")])
    order: list[bytes] = []
    real = v._reverify_block

    async def spy(bid, row):
        order.append(bid)
        return await real(bid, row)

    v._reverify_block = spy
    blocks[2][2].mock(return_value=UNAVAILABLE)
    cut = await v.scheduled_reverify()
    assert (cut.checked, cut.complete) == (2, False)
    status = (await store.service_status())["reverify"]
    assert status["status"] == "retrying (node unavailable)"
    assert "stopped after 2 blocks" in status["detail"]

    blocks[2][2].mock(return_value=binary(make_block({"score": 0.5, "id": "MyDomain:c"})[0]))
    order.clear()
    full = await v.scheduled_reverify()
    assert (full.checked, full.complete) == (4, True)
    # Round robin: the next pass starts at the block the last one could not judge.
    ids = [b[0] for b in blocks]
    assert order == [ids[2], ids[3], ids[0], ids[1]]
    assert (await store.service_status())["reverify"]["status"] == "ok"
    order.clear()
    await v.reverify_pass()
    assert order == [ids[2], ids[3], ids[0], ids[1]]


@respx.mock
async def test_scheduled_pass_with_nothing_to_check(env):
    _, v, _ = env
    assert await v.reverify_pass() == PassResult(0, [], True)
    assert (await v.scheduled_reverify()).complete


# -- what re-verification leaves to the validator's own alerts -------------------------------


async def mismatched_block(store, v, name):
    """Forwarded bytes differ from the Tangle: the validator concludes CONTENT_MISMATCH and
    raises its own alert; the stored copy still differs from the Tangle afterwards."""
    raw, bid, data = make_block({"score": 0.5, "id": f"MyDomain:{name}"})
    _, block_route = serve(bid, raw, confirmed_always(bid))
    await handle_record(store, RecordingValidator(),
                        rec(f"s-{name}", bid, data.replace(b"0.5", b"0.7")), source="mqtt")
    assert await v.validate_once(bid, f"s-{name}") == "CONTENT_MISMATCH"
    return bid, block_route


@respx.mock
async def test_already_alerted_outcomes_get_no_db_tamper(env):
    store, v, _ = env
    _, mism_route = await mismatched_block(store, v, "m")
    # NOT_FOUND: confirmed, but the node does not return the block.
    _, gone, data_n = make_block({"id": "gone"})
    serve(gone, None, confirmed_always(gone))
    await handle_record(store, RecordingValidator(), rec("s-n", gone, data_n), source="mqtt")
    assert await v.validate_once(gone, "s-n") == "NOT_FOUND"
    # A verified block that is then tampered with is still DB_TAMPER.
    bid, data, _ = await verified_block(store, v, "ok")
    await store._fetch(*tamper_sql(bid))

    calls = mism_route.call_count
    [alert] = await v.reverify_all()
    assert (alert.rule, alert.severity, alert.block_id) == ("DB_TAMPER", "critical", bid)
    assert mism_route.call_count == calls  # not even fetched
    assert sorted(a["rule"] for a in await store.alerts()) == [
        "CONTENT_MISMATCH", "DB_TAMPER", "NOT_FOUND"]
    # Its own DB_TAMPER row does not turn it into an exempt CONTENT_MISMATCH: deduplicated
    # while unchanged, a new tampering is reported again.
    assert (await statuses(store, bid))[-1] == "CONTENT_MISMATCH"
    assert await v.reverify_all() == []
    await tamper_submission(store, bid, "0x" + data.replace(b"0.5", b"0.1").hex())
    [again] = await v.reverify_all()
    assert (again.rule, again.block_id) == ("DB_TAMPER", bid)
    assert (await v.scheduled_reverify()).alerts == []


@respx.mock
async def test_an_outcome_without_its_alert_exempts_nothing(env):
    store, v, _ = env
    mism, _ = await mismatched_block(store, v, "m")
    # The alert's severity is not the validator's: no exemption.
    await store._fetch("UPDATE alerts SET severity = 'low' WHERE block_id = %s RETURNING 1",
                       (mism,))
    [alert] = await v.reverify_all()
    assert (alert.rule, alert.block_id) == ("DB_TAMPER", mism)
    other, _ = await mismatched_block(store, v, "n")
    await store._fetch("DELETE FROM alerts WHERE block_id = %s RETURNING 1", (other,))
    [alert] = await v.reverify_all()
    assert (alert.rule, alert.block_id) == ("DB_TAMPER", other)


@respx.mock
async def test_the_message_copy_of_an_alerted_block_is_still_judged(env):
    """A CONTENT_MISMATCH alert is about the forwarded copy. The indexed message copy (the
    Tangle's bytes) is still held to the Tangle: rewriting it is DB_TAMPER."""
    store, v, _ = env
    raw, bid, data = make_block({"score": 0.5, "id": "MyDomain:mm"})
    serve(bid, raw, confirmed_always(bid))
    await handle_record(store, RecordingValidator(),
                        rec("s-mm", bid, data.replace(b"0.5", b"0.7")), source="mqtt")
    await store.put_message(MessageRow(block_id=bid, tag="trust.score", data=data))
    assert await v.validate_once(bid, "s-mm") == "CONTENT_MISMATCH"
    assert await v.reverify_all() == []  # only the submission copy differs: already alerted
    await store._fetch(*tamper_sql(bid))
    [alert] = await v.reverify_all()
    assert (alert.rule, alert.severity, alert.block_id) == ("DB_TAMPER", "critical", bid)
    assert [f["field"] for f in alert.evidence["fields"]] == ["messages.data"]
    assert await v.reverify_all() == []  # deduplicated


@respx.mock
async def test_a_block_verified_after_its_orphan_alert_is_judged(env):
    store, v, _ = env
    bid, data, _ = await verified_block(store, v, "late")
    # It went ORPHANED (with its alert) before a milestone referenced it; the latest outcome
    # is the later CONTENT_VERIFIED, so its stored copies are held to the Tangle again.
    await store.set_lifecycle(block_id=bid, sub_id="s-late", status="ORPHANED", at_ms=1)
    await store.put_alert(Alert("ORPHANED", "high", bid, None, {}, 1))
    await tamper_submission(store, bid, "0x" + data.replace(b"0.5", b"0.9").hex())
    [alert] = await v.reverify_all()
    assert (alert.rule, alert.block_id) == ("DB_TAMPER", bid)


@respx.mock
async def test_a_full_tangle_cache_keeps_what_it_holds(env):
    store, v, _ = env
    v.cfg = ValidatorConfig(reverify_batch=2, tangle_cache_size=2)
    blocks = sorted([await verified_block(store, v, n) for n in ("a", "b", "c")])
    await v.reverify_pass()
    routes = [route for _, _, route in blocks]
    before = [r.call_count for r in routes]
    await v.reverify_pass()
    await v.reverify_pass()
    # The first two stay cached; only the one that did not fit is fetched each pass.
    assert [r.call_count - b for r, b in zip(routes, before, strict=True)] == [0, 0, 2]
