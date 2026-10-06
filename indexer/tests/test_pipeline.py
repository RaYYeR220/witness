import asyncio
import dataclasses
import json
import logging

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fakechain import FakeChain, FakeSource, did_key, signed, tamper
from witness_core import canon, codec, envelope, merkle, policy
from witness_core.envelope import KeyInfo
from witness_indexer.didkey import OfflineResolver
from witness_indexer.pipeline import Indexer
from witness_indexer.source import ConeBlock, SourceUnavailable
from witness_indexer.store import Alert, MessageFilter, MessageRow, Store, Submission

ALICE = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
BOB = Ed25519PrivateKey.from_private_bytes(b"\x02" * 32)
CAROL = Ed25519PrivateKey.from_private_bytes(b"\x03" * 32)
RELAY = Ed25519PrivateKey.from_private_bytes(b"\x04" * 32)

POLICY = policy.load({
    "version": 1,
    "tags": {
        "trust.score": {"allowed": [did_key(ALICE), did_key(CAROL), did_key(RELAY)],
                        "require_signature": False, "legacy_grace": True},
    },
    "default": {"allowed": ["*"]},
})


def score(ie: str, value: float) -> dict:
    return {"id": ie, "score": value}


def indexer(source, store: Store, **kw) -> Indexer:
    kw.setdefault("policy", POLICY)
    kw.setdefault("resolve", OfflineResolver())
    kw.setdefault("sleep", _no_sleep)
    return Indexer(source, store, **kw)


async def _no_sleep(_s: float) -> None:
    await asyncio.sleep(0)


async def wait_cursor(store: Store, index: int, timeout: float = 10.0) -> None:
    async def poll() -> None:
        while await store.get_cursor() < index:
            await asyncio.sleep(0.02)

    await asyncio.wait_for(poll(), timeout)


async def msg(store: Store, block_id: bytes) -> dict:
    row = await store.get_message(block_id)
    assert row is not None, f"message 0x{block_id.hex()} not stored"
    return row


async def event_types(store: Store) -> list[str]:
    return [e["type"] for e in await store.events_after(0, 10_000)]


# -- sources, cursor, resume -------------------------------------------------------------------


async def test_backfill_then_tail(store: Store):
    chain = FakeChain()
    for i in range(5):
        chain.add([("trust.score", json.dumps(score("D:aabbccddeeff", i / 10)).encode())])
    src = FakeSource(chain, tail=True)
    ix = indexer(src, store)
    task = asyncio.create_task(ix.run())
    await wait_cursor(store, 5)
    chain.add([("LLO-K8s", b'{"event":"deploy","lloId":"l1","serviceComponentId":"s1"}')])
    await wait_cursor(store, 6)
    await ix.stop()
    await task

    assert await store.get_cursor() == 6
    assert src.starts == [1]
    for i in range(1, 7):
        stored = await store.milestone(i)
        assert stored["id"] == chain.ms[i].id
        assert stored["essence"] == chain.ms[i].essence
        assert stored["inclusion_root"] == chain.ms[i].inclusion_root
        assert stored["prev_id"] == chain.ms[i].prev_id
        assert stored["sigs"] == chain.ms[i].signature_dicts()
        assert await store.cone_ids(i) == [b.block_id for b in chain.cones[i]]
    stats = await store.stats()
    assert (stats["milestones"], stats["blocks"], stats["messages"]) == (6, 11, 6)
    last = await msg(store, chain.block_id(6, 0))
    assert (last["ms_index"], last["wf_index"], last["ts"]) == (6, 1, chain.ms[6].timestamp)
    assert last["kind"] == "llo.k8s" and last["tag"] == "LLO-K8s"
    types = await event_types(store)
    assert types.count("milestone") == 6 and types.count("message") == 6


async def test_milestone_blocks_stored_with_payload_type(store: Store):
    chain = FakeChain()
    chain.add([("t", b"{}")])
    chain.add([])
    await indexer(FakeSource(chain), store).sync()
    rows = await store._fetch("SELECT id, payload_type, ms_index, wf_index, raw FROM blocks "
                              "ORDER BY ms_index, wf_index")
    assert [(r["ms_index"], r["wf_index"], r["payload_type"]) for r in rows] == [
        (1, 0, codec.PAYLOAD_TAGGED_DATA), (2, 0, codec.PAYLOAD_MILESTONE)]
    assert all(codec.block_id(r["raw"]) == r["id"] for r in rows)


async def test_resume_after_disconnect(store: Store):
    chain = FakeChain()
    for i in range(5):
        chain.add([("trust.score", json.dumps(score("D:aabbccddeeff", i / 10)).encode()),
                   ("LLO-K8s", b'{"event":"e","lloId":"l","serviceComponentId":"s"}')])
    src = FakeSource(chain, fail_after=3)
    ix = indexer(src, store)
    with pytest.raises(SourceUnavailable):
        await ix.sync()
    assert await store.get_cursor() == 3
    assert await store.milestone(4) is None

    assert await indexer(src, store).sync() == 5  # a restarted process
    assert src.starts == [1, 4]
    stats = await store.stats()
    assert (stats["milestones"], stats["blocks"], stats["messages"]) == (5, 14, 10)
    types = await event_types(store)
    assert types.count("milestone") == 5 and types.count("message") == 10
    assert len(await store._fetch("SELECT * FROM ie_scores")) == 5


async def test_run_reconnects_after_disconnect(store: Store):
    chain = FakeChain()
    for _ in range(5):
        chain.add([("x", b"{}")])
    sleeps: list[float] = []

    async def sleep(s: float) -> None:
        sleeps.append(s)
        await asyncio.sleep(0)

    src = FakeSource(chain, fail_after=2, tail=True)
    ix = indexer(src, store, sleep=sleep)
    task = asyncio.create_task(ix.run())
    await wait_cursor(store, 5)
    await ix.stop()
    await task
    assert src.starts == [1, 3]
    assert sleeps and sleeps[0] == pytest.approx(0.5)
    assert (await store.stats())["milestones"] == 5


async def test_stop_lets_the_current_milestone_commit(store: Store):
    entered, release = asyncio.Event(), asyncio.Event()

    class SlowRules:
        async def on_message(self, row):
            entered.set()
            await release.wait()
            return []

    chain = FakeChain()
    chain.add([("x", b"{}")])
    src = FakeSource(chain, tail=True)
    ix = indexer(src, store, rules=SlowRules())
    task = asyncio.create_task(ix.run())
    await asyncio.wait_for(entered.wait(), 10)
    stopping = asyncio.create_task(ix.stop())
    await asyncio.sleep(0.1)
    assert not stopping.done()  # waits for the open transaction instead of cancelling it
    release.set()
    await asyncio.wait_for(stopping, 10)
    await task
    assert await store.get_cursor() == 1
    assert (await store.stats())["messages"] == 1


async def test_reprocess_same_milestone_is_idempotent(store: Store):
    chain = FakeChain()
    chain.add([("trust.score", json.dumps(score("D:aabbccddeeff", 0.5)).encode()),
               ("trust.score", signed(ALICE, "trust.score", score("D:aabbccddeeff", 0.6), 1))])
    chain.add([("x", b"{}")])
    ix = indexer(FakeSource(chain), store)
    await ix.sync()
    before = (await store.stats(), await store.events_after(0, 1000))
    for i in (2, 1):
        await ix.process_milestone(chain.ms[i])  # e.g. an INX stream resent after reconnect
    after = (await store.stats(), await store.events_after(0, 1000))
    assert after == before
    assert await store.get_cursor() == 2  # an old milestone never moves the cursor back
    assert (await msg(store, chain.block_id(1, 1)))["verdict"] == "PRODUCER_SIGNED"


async def test_duplicate_milestones_from_source_are_skipped(store: Store):
    chain = FakeChain()
    for _ in range(3):
        chain.add([("x", b"{}")])

    class Repeating(FakeSource):
        async def milestones(self, start):
            for i in (1, 2, 2, 1, 3):
                yield self.chain.ms[i]

    await indexer(Repeating(chain), store).sync()
    assert (await event_types(store)).count("milestone") == 3


async def test_cone_root_mismatch_is_logged(store: Store, caplog):
    chain = FakeChain()
    chain.add([("x", b"{}"), ("y", b"{}")])
    chain.cones[1] = chain.cones[1][:1]  # the node "forgot" a block
    with caplog.at_level(logging.ERROR, logger="witness_indexer.pipeline"):
        await indexer(FakeSource(chain), store).sync()
    assert "inclusion" in caplog.text
    assert (await store.stats())["milestones"] == 1


# -- verdicts ----------------------------------------------------------------------------------


async def test_verdict_pipeline(store: Store):
    revoked_at = (1_790_000_000 + 5 * 3) * 1000  # milestone 3's timestamp, in ms
    carol_kid = f"{did_key(CAROL)}#{did_key(CAROL)[len('did:key:'):]}"
    resolver = OfflineResolver({
        carol_kid: KeyInfo(carol_kid, CAROL.public_key().public_bytes_raw(), None, revoked_at)})
    ie = "D:aabbccddeeff"
    first = signed(ALICE, "trust.score", score(ie, 0.9), 1)
    chain = FakeChain()
    chain.add([
        ("trust.score", first),                                           # 0
        ("trust.score", signed(BOB, "trust.score", score(ie, 0.1), 1)),   # 1
        ("trust.score", json.dumps(score(ie, 0.8)).encode()),             # 2
        ("trust.score", tamper(signed(ALICE, "trust.score", score(ie, 0.7), 2), score=0.01)),
        ("trust.score", signed(CAROL, "trust.score", score(ie, 0.5), 1)),  # 4
        ("trust.score", signed(RELAY, "trust.score", score(ie, 0.4), 1, mode="relay")),  # 5
        ("LLO-K8s", signed(ALICE, "trust.score", score(ie, 0.3), 3)),     # 6 tag mismatch
        ("trust.score", b'{"w":1,"sig":"x","body":{}}'),                   # 7
    ])
    chain.add([
        ("trust.score", signed(ALICE, "trust.score", score(ie, 0.6), 1, nonce=b"n" * 16)),
        ("trust.score", signed(ALICE, "trust.score", score(ie, 0.6), 9,
                               nonce=(1).to_bytes(16, "big"))),           # nonce of `first`
        ("trust.score", signed(ALICE, "trust.score", score(ie, 0.6), 10)),
    ])
    chain.add([("trust.score", signed(CAROL, "trust.score", score(ie, 0.2), 2))])

    await indexer(FakeSource(chain), store, resolve=resolver).sync()

    async def verdict(index: int, n: int) -> str:
        return (await msg(store, chain.block_id(index, n)))["verdict"]

    assert [await verdict(1, n) for n in range(8)] == [
        "PRODUCER_SIGNED", "UNAUTHORIZED_WRITER", "UNSIGNED_LEGACY", "FORGED",
        "PRODUCER_SIGNED", "RELAY_ATTESTED", "FORGED", "MALFORMED"]
    assert [await verdict(2, n) for n in range(3)] == ["REPLAY", "REPLAY", "PRODUCER_SIGNED"]
    assert await verdict(3, 0) == "REVOKED_KEY"

    row = await msg(store, chain.block_id(1, 0))
    env = json.loads(first)
    assert row["iss"] == did_key(ALICE) and row["kid"] == env["kid"]
    assert (row["seq"], row["iat"], row["nonce"]) == (1, env["iat"], env["nonce"])
    assert row["json"] == score(ie, 0.9) and row["ie_id"] == ie
    assert row["canon_hash"] == canon.canon_hash(score(ie, 0.9))
    assert row["data"] == first and row["kind"] == "trust.score"
    assert row["encrypted"] is False


async def test_sealed_envelope_keeps_blind_tokens(store: Store):
    did = did_key(ALICE)
    sealed = envelope.seal("trust.score", None, iss=did, kid=f"{did}#{did[len('did:key:'):]}",
                           sign_key=ALICE, seq=1,
                           att_mode="producer", enc={"ciphertext": "AA", "recipients": []},
                           bix=["tok-ie", "tok-tag"], corr="incident-7",
                           prev="0x" + "ab" * 32, now_ms=1)
    chain = FakeChain()
    chain.add([("trust.score", json.dumps(sealed).encode())])
    await indexer(FakeSource(chain), store).sync()
    bid = chain.block_id(1, 0)
    row = await msg(store, bid)
    assert row["verdict"] == "PRODUCER_SIGNED"
    assert row["encrypted"] is True and row["json"] is None and row["canon_hash"] is None
    assert row["corr"] == "incident-7" and row["prev"] == b"\xab" * 32
    found = await store.lookup_blind(["tok-ie", "tok-tag", "nope"])
    assert sorted(r["token"] for r in found) == ["tok-ie", "tok-tag"]
    assert {r["block_id"] for r in found} == {bid}
    assert await store._fetch("SELECT * FROM ie_scores") == []


async def test_replay_within_one_milestone(store: Store):
    chain = FakeChain()
    chain.add([("trust.score", signed(ALICE, "trust.score", score("D:aabbccddeeff", 0.5), 4)),
               ("trust.score", signed(ALICE, "trust.score", score("D:aabbccddeeff", 0.5), 4,
                                      nonce=b"z" * 16))])
    await indexer(FakeSource(chain), store).sync()
    assert [(await msg(store, chain.block_id(1, n)))["verdict"] for n in (0, 1)] == [
        "PRODUCER_SIGNED", "REPLAY"]


# -- awkward payloads --------------------------------------------------------------------------


async def test_non_json_payloads_indexed(store: Store):
    payloads = [
        ("witness.binary", bytes([0x00, 0xFF, 0xFE, 0x80, 0x01, 0xC3, 0x28])),
        ("LLO-K8s", b'[{"node":"a","cpu":12},{"node":"b","cpu":80}]'),
        ("self-orchestrator", b'{"infrastructureElementId": "x", "errorCo'),
        ("trust.score", b"42"),
        ("plain", b"plain text, not json"),
        ("nul.json", b'{"a":"\\u0000"}'),
        ("surrogate", b'{"a":"\\ud800"}'),
        ("nul.key", b'{"\\u0000":1}'),
        (b"\xff\xfe", b'{"tag":"not utf-8"}'),
        (b"a\x00b", b"{}"),
        ("empty", b""),
        ("deep", b"[" * 5000 + b"]" * 5000),
        ("nan", b'{"score": NaN}'),
        ("overflow", b'{"x": 1e999}'),
        ("trust.score", signed(ALICE, "trust.score", {"id": "D:aabbccddeeff",
                                                      "score": "\u0000"}, 1)),
    ]
    chain = FakeChain()
    chain.add(payloads)
    await indexer(FakeSource(chain), store).sync()

    rows = [await msg(store, chain.block_id(1, n)) for n in range(len(payloads))]
    for (tag, data), row in zip(payloads, rows, strict=True):
        assert row["data"] == data and row["ms_index"] == 1
    kinds = [r["kind"] for r in rows]
    assert kinds[:8] == ["unknown"] * 8
    assert [r["verdict"] for r in rows[:5]] == [
        "UNSIGNED_LEGACY", "MALFORMED", "MALFORMED", "MALFORMED", "UNSIGNED_LEGACY"]
    assert rows[1]["json"] == [{"node": "a", "cpu": 12}, {"node": "b", "cpu": 80}]
    assert rows[0]["json"] is None and rows[2]["json"] is None
    assert rows[5]["json"] is None and rows[6]["json"] is None and rows[7]["json"] is None
    assert rows[8]["tag"] == "0xfffe" and rows[9]["tag"] == "0x610062"
    assert rows[13]["json"] is None and rows[13]["canon_hash"] is None
    assert rows[14]["verdict"] == "PRODUCER_SIGNED" and rows[14]["json"] is None
    found, _ = await store.query_messages(MessageFilter(tag="witness.binary"), None, 10)
    assert [r["block_id"] for r in found] == [chain.block_id(1, 0)]
    assert await store.get_cursor() == 1


async def test_undecodable_cone_block_is_stored(store: Store):
    chain = FakeChain()
    chain.add([("x", b"{}")])
    junk = b"\x02\x01" + bytes(32) + b"\xff\xff"
    cone = chain.cones[1] + [ConeBlock(codec.block_id(junk), junk, 1)]
    chain.cones[1] = cone
    chain.ms[1] = dataclasses.replace(chain.ms[1],
                                      inclusion_root=merkle.root([b.block_id for b in cone]))
    await indexer(FakeSource(chain), store).sync()
    rows = await store._fetch("SELECT wf_index, payload_type FROM blocks ORDER BY wf_index")
    assert [(r["wf_index"], r["payload_type"]) for r in rows] == [(0, 5), (1, -1)]


# -- trust score lineage, lifecycle, rules -------------------------------------------------------


async def test_trust_score_lineage(store: Store):
    ie = "MyDomain:fa163e5e25ef"
    chain = FakeChain()
    for value in (0.9, 0.5, 0.7):
        chain.add([("trust.score", json.dumps(score(ie, value)).encode()),
                   ("trust.score", json.dumps(score("Other:aabbccddeeff", 0.1)).encode())])
    chain.add([("trust.score", json.dumps({"id": ie, "score": 7}).encode())])  # out of range
    await indexer(FakeSource(chain), store).sync()
    rows = await store._fetch(
        "SELECT ms_index, ts, score, block_id, verdict FROM ie_scores WHERE ie_id = %s "
        "ORDER BY ms_index", (ie,))
    assert [r["score"] for r in rows] == [0.9, 0.5, 0.7]
    assert [r["ms_index"] for r in rows] == [1, 2, 3]
    assert [r["ts"] for r in rows] == [chain.ms[i].timestamp for i in (1, 2, 3)]
    assert [r["block_id"] for r in rows] == [chain.block_id(i, 0) for i in (1, 2, 3)]
    assert {r["verdict"] for r in rows} == {"UNSIGNED_LEGACY"}
    assert [r["block_id"] for r in await store.ie_lineage(ie)][:3] == [
        chain.block_id(i, 0) for i in (1, 2, 3)]


async def test_submitted_message_is_confirmed_by_the_indexer(store: Store):
    chain = FakeChain()
    chain.add([("trust.score", json.dumps(score("D:aabbccddeeff", 0.5)).encode()),
               ("trust.score", json.dumps(score("D:aabbccddeeff", 0.6)).encode()),
               ("trust.score", json.dumps(score("D:aabbccddeeff", 0.7)).encode()),
               ("trust.score", json.dumps(score("D:aabbccddeeff", 0.8)).encode())])
    sub_only, seen_first, verified, shadow = (chain.block_id(1, n) for n in range(4))
    for n, b in enumerate((sub_only, seen_first, verified)):
        await store.put_submission(Submission(f"s{n}", "mqtt", 1_000 + n, tag="trust.score",
                                              block_id=b))
        await store.set_lifecycle(block_id=b, sub_id=f"s{n}", status="RECEIVED", at_ms=2_000)
        await store.set_lifecycle(block_id=b, sub_id=f"s{n}", status="SUBMITTED", at_ms=2_001)
    # a row the API side already wrote before the block was confirmed
    assert await store.put_message(MessageRow(block_id=seen_first, tag="trust.score",
                                              kind="trust.score")) == "inserted"
    await store.set_lifecycle(block_id=verified, sub_id="s2", status="CONTENT_VERIFIED",
                              at_ms=2_002)

    await indexer(FakeSource(chain), store).sync()

    def statuses(rows):
        return [r["status"] for r in rows]

    assert statuses(await store.lifecycle(sub_only))[-1] == "CONFIRMED"
    assert statuses(await store.lifecycle(seen_first))[-1] == "CONFIRMED"
    assert statuses(await store.lifecycle(verified)) == [
        "RECEIVED", "SUBMITTED", "CONTENT_VERIFIED"]
    assert await store.lifecycle(shadow) == []

    row = await msg(store, sub_only)
    assert row["status"] == "CONFIRMED" and row["received_at_ms"] == 1_000
    assert row["confirmed_at_ms"] == chain.ms[1].timestamp * 1000
    row = await msg(store, seen_first)
    assert (row["ms_index"], row["verdict"], row["status"]) == (1, "UNSIGNED_LEGACY",
                                                                  "CONFIRMED")
    assert (await msg(store, shadow))["status"] is None
    assert (await event_types(store)).count("lifecycle") == 2


class RecordingRules:
    def __init__(self) -> None:
        self.seen: list[MessageRow] = []

    def on_message(self, row: MessageRow) -> list[Alert]:
        self.seen.append(row)
        if row.verdict == "UNSIGNED_LEGACY":
            return []
        return [Alert("VERDICT", "high", row.block_id, row.ie_id, {"verdict": row.verdict},
                      row.ts * 1000)]


class AsyncRules(RecordingRules):
    async def on_message(self, row: MessageRow) -> list[Alert]:  # type: ignore[override]
        await asyncio.sleep(0)
        return super().on_message(row)


@pytest.mark.parametrize("rules_cls", [RecordingRules, AsyncRules])
async def test_rules_hook_persists_alerts(store: Store, rules_cls):
    chain = FakeChain()
    chain.add([("trust.score", json.dumps(score("D:aabbccddeeff", 0.5)).encode()),
               ("trust.score", signed(BOB, "trust.score", score("D:aabbccddeeff", 0.1), 1))])
    rules = rules_cls()
    ix = indexer(FakeSource(chain), store, rules=rules)
    await ix.sync()
    await ix.process_milestone(chain.ms[1])
    assert [r.verdict for r in rules.seen] == ["UNSIGNED_LEGACY", "UNAUTHORIZED_WRITER"]
    assert rules.seen[1].ms_index == 1 and rules.seen[1].wf_index == 1
    alerts = await store.alerts()
    assert [(a["rule"], a["block_id"]) for a in alerts] == [("VERDICT", chain.block_id(1, 1))]
    assert (await event_types(store)).count("alert") == 1


async def test_failed_rules_roll_back_the_milestone(store: Store):
    class Broken:
        def on_message(self, row):
            raise RuntimeError("rules engine bug")

    chain = FakeChain()
    chain.add([("x", b"{}")])
    with pytest.raises(RuntimeError):
        await indexer(FakeSource(chain), store, rules=Broken()).sync()
    stats = await store.stats()
    assert (stats["milestones"], stats["messages"], stats["events"], stats["cursor"]) == (
        0, 0, 0, 0)
