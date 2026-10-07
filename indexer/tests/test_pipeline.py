import asyncio
import dataclasses
import json
from urllib.parse import quote

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fakechain import FakeChain, FakeSource, did_key, signed, tamper
from witness_core import canon, codec, envelope, merkle, policy
from witness_core.envelope import KeyInfo
from witness_indexer.classify import ResolverFailed
from witness_indexer.didkey import OfflineResolver
from witness_indexer.pipeline import ALLOW_ALL, Indexer
from witness_indexer.resolver import DidResolver
from witness_indexer.rules import RulesEngine
from witness_indexer.source import (
    ConeBlock,
    ConeMismatch,
    NetworkChanged,
    SourceUnavailable,
)
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


async def test_cone_root_mismatch_is_refused(store: Store):
    chain = FakeChain()
    chain.add([("x", b"{}"), ("y", b"{}")])
    chain.cones[1] = chain.cones[1][:1]  # the node "forgot" a block
    with pytest.raises(ConeMismatch):
        await indexer(FakeSource(chain), store).sync()
    stats = await store.stats()
    assert (stats["milestones"], stats["blocks"], stats["messages"], stats["cursor"]) == (
        0, 0, 0, 0)


async def test_stuck_milestone_is_reported_then_recovers(store: Store):
    chain = FakeChain()
    chain.add([("x", b"{}")])
    chain.add([("x", b"{}"), ("y", b"{}")])
    good = chain.cones[2]
    chain.cones[2] = good[:1]
    seen: list[str] = []

    async def sleep(_s):
        seen.append((await store.stats()).get("indexer"))
        if len(seen) == 7:
            chain.cones[2] = good  # the node is fixed
        await asyncio.sleep(0)

    ix = indexer(FakeSource(chain, tail=True), store, sleep=sleep)
    task = asyncio.create_task(ix.run())
    await wait_cursor(store, 2)
    await ix.stop()
    await task
    assert seen[:4] == [f"retrying milestone 2 (cone root mismatch, attempt {n})"
                        for n in range(1, 5)]
    assert seen[4:7] == ["stuck at 2 (cone root mismatch)"] * 3
    assert (await store.stats())["indexer"] == "ok"


async def test_transient_source_errors_never_count_as_stuck(store: Store):
    chain = FakeChain()
    chain.add([("x", b"{}")])

    class Flaky(FakeSource):
        failures = 8

        async def milestones(self, start):
            if self.failures:
                self.failures -= 1
                raise SourceUnavailable("connection refused")
            async for m in super().milestones(start):
                yield m

    seen = []

    async def sleep(_s):
        seen.append((await store.stats()).get("indexer"))
        await asyncio.sleep(0)

    ix = indexer(Flaky(chain, tail=True), store, sleep=sleep)
    task = asyncio.create_task(ix.run())
    await wait_cursor(store, 1)
    await ix.stop()
    await task
    assert seen == ["retrying (fake unavailable)"] * 8
    assert (await store.stats())["indexer"] == "ok"


async def test_network_change_is_refused(store: Store):
    a, b = FakeChain(), FakeChain()
    for chain, tag in ((a, "a"), (b, "b")):
        for _ in range(3):
            chain.add([(tag, b"{}")])
    del a.ms[3]
    await indexer(FakeSource(a), store).sync()
    assert await store.get_cursor() == 2
    with pytest.raises(NetworkChanged):  # b's milestone 3 does not follow a's milestone 2
        await indexer(FakeSource(b), store).sync()
    with pytest.raises(NetworkChanged):  # same index, different milestone
        await indexer(FakeSource(b), store).process_milestone(b.ms[2])
    stats = await store.stats()
    assert (stats["milestones"], stats["cursor"]) == (2, 2)

    seen = []

    async def sleep(_s):
        seen.append((await store.stats()).get("indexer"))
        await asyncio.sleep(0)

    ix = indexer(FakeSource(b, tail=True), store, sleep=sleep)
    task = asyncio.create_task(ix.run())
    while not seen:
        await asyncio.sleep(0.01)
    await ix.stop()
    await task
    assert seen[0] == "network changed"
    assert (await store.service_status())["indexer"]["detail"].startswith("milestone 3")


# -- verdicts ----------------------------------------------------------------------------------


async def test_verdict_pipeline(store: Store):
    revoked_at = (1_790_000_000 + 5 * 3) * 1000 - 1  # just before milestone 3, in ms
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
    assert (await store.stats())["policy"] == "file"

    row = await msg(store, chain.block_id(1, 0))
    env = json.loads(first)
    assert row["iss"] == did_key(ALICE) and row["kid"] == env["kid"]
    assert (row["seq"], row["iat"], row["nonce"]) == (1, env["iat"], env["nonce"])
    assert row["json"] == score(ie, 0.9) and row["ie_id"] == ie
    assert row["canon_hash"] == canon.canon_hash(score(ie, 0.9))
    assert row["data"] == first and row["kind"] == "trust.score"
    assert row["encrypted"] is False


async def test_key_revoked_inside_the_milestone_second_is_revoked(store: Store):
    """Milestone timestamps have second precision: a revocation anywhere in the milestone's
    second (or before it) revokes; one at the next second does not."""
    ie = "D:aabbccddeeff"
    signers = (CAROL, ALICE, BOB, RELAY)
    chain = FakeChain()
    chain.add([("trust.score", signed(sk, "trust.score", score(ie, 0.5), 1)) for sk in signers])
    at = chain.ms[1].timestamp * 1000
    when = (at + 1000, at + 999, at, at - 1)
    pinned = {kid_of(sk): KeyInfo(kid_of(sk), sk.public_key().public_bytes_raw(), None, t)
              for sk, t in zip(signers, when, strict=True)}
    await indexer(FakeSource(chain), store, resolve=OfflineResolver(pinned),
                  policy=ALLOW_ALL).sync()
    assert [(await msg(store, chain.block_id(1, n)))["verdict"] for n in range(4)] == [
        "PRODUCER_SIGNED", "REVOKED_KEY", "REVOKED_KEY", "REVOKED_KEY"]


async def test_signed_body_that_breaks_the_schema_is_malformed(store: Store):
    """A valid signature does not rescue a body that breaks its tag's schema: the message is
    MALFORMED, and the row still says who signed it. A sealed body cannot be inspected and
    stays signed; a tag without a schema accepts any object."""
    ie = "D:aabbccddeeff"
    chain = FakeChain()
    chain.add([
        ("trust.score", signed(ALICE, "trust.score", {"id": "not-an-ie-id", "score": 7}, 1)),
        ("trust.score", signed(ALICE, "trust.score", score(ie, 1.5), 2)),
        ("audit.report", signed(RELAY, "audit.report", {"reportId": "r1"}, 1, mode="relay")),
        ("audit.report", signed(RELAY, "audit.report", None, 2, mode="relay",
                                enc={"protected": "x", "ciphertext": "y"})),
        ("trust.score", signed(ALICE, "trust.score", score(ie, 0.5), 4)),
        ("some.tag", signed(ALICE, "some.tag", {"anything": True}, 5)),
    ])
    rules = RulesEngine(store, None, DidResolver(None), ALLOW_ALL)
    await indexer(FakeSource(chain), store, policy=ALLOW_ALL, rules=rules).sync()

    rows = [await msg(store, chain.block_id(1, n)) for n in range(6)]
    assert [r["verdict"] for r in rows] == [
        "MALFORMED", "MALFORMED", "MALFORMED", "RELAY_ATTESTED", "PRODUCER_SIGNED",
        "PRODUCER_SIGNED"]
    assert [(r["iss"], r["kid"], r["seq"]) for r in rows[:3]] == [
        (did_key(ALICE), kid_of(ALICE), 1), (did_key(ALICE), kid_of(ALICE), 2),
        (did_key(RELAY), kid_of(RELAY), 1)]
    # A broken body is no trust score, even when its IE id is fine.
    assert rows[1]["ie_id"] == ie
    scored = await store._fetch("SELECT block_id FROM ie_scores WHERE ie_id = %s", (ie,))
    assert [bytes(r["block_id"]) for r in scored] == [chain.block_id(1, 4)]

    events = [e["payload"] for e in await store.events_after(0, 100) if e["type"] == "message"]
    assert events[0]["reason"] == "signed, but the body breaks the trust.score schema"
    alerts = {bytes(a["block_id"]): a["evidence"] for a in await store.alerts({"rule": "MALFORMED"})}
    assert set(alerts) == {chain.block_id(1, n) for n in range(3)}
    assert alerts[chain.block_id(1, 0)] == {
        "tag": "trust.score", "kind": "trust.score",
        "reason": "envelope body breaks the trust.score schema",
        "signature": {"verified": True, "iss": did_key(ALICE), "kid": kid_of(ALICE), "seq": 1,
                      "mode": "producer"}}
    assert alerts[chain.block_id(1, 2)]["signature"]["mode"] == "relay"


async def test_a_null_body_is_malformed_on_every_tag(store: Store):
    """The envelope format allows `body: null`, but no tag's body may be anything but a JSON
    object, schema or not."""
    chain = FakeChain()
    chain.add([("some.tag", signed(ALICE, "some.tag", None, 1)),
               ("trust.score", signed(ALICE, "trust.score", None, 2))])
    await indexer(FakeSource(chain), store, policy=ALLOW_ALL).sync()
    assert [(await msg(store, chain.block_id(1, n)))["verdict"] for n in (0, 1)] == [
        "MALFORMED", "MALFORMED"]
    reasons = [e["payload"]["reason"] for e in await store.events_after(0, 100)
               if e["type"] == "message"]
    assert reasons == ["signed, but the body is not a JSON object"] * 2


async def test_a_malformed_message_does_not_spend_its_seq(store: Store):
    """A validly signed message with a broken body is MALFORMED and does not use up its seq
    or nonce: the producer's corrected message with the same seq is accepted (the relay
    likewise refuses the broken one before claiming the seq)."""
    ie = "D:aabbccddeeff"
    chain = FakeChain()
    chain.add([("trust.score", signed(ALICE, "trust.score", score(ie, 7), 5))])
    chain.add([("trust.score", signed(ALICE, "trust.score", score(ie, 0.7), 5,
                                      nonce=b"f" * 16))])
    await indexer(FakeSource(chain), store).sync()
    assert [(await msg(store, chain.block_id(i, 0)))["verdict"] for i in (1, 2)] == [
        "MALFORMED", "PRODUCER_SIGNED"]


async def test_out_of_order_seqs_are_not_replays(store: Store):
    ie = "D:aabbccddeeff"
    chain = FakeChain()
    chain.add([("trust.score", signed(ALICE, "trust.score", score(ie, 0.2), 2)),
               ("trust.score", signed(ALICE, "trust.score", score(ie, 0.1), 1))])
    chain.add([("trust.score", signed(ALICE, "trust.score", score(ie, 0.3), 1,
                                      nonce=b"q" * 16)),                # seq 1 again
               ("trust.score", signed(ALICE, "trust.score", score(ie, 0.3), 7,
                                      nonce=(2).to_bytes(16, "big"))),  # nonce of seq 2
               ("trust.score", signed(ALICE, "trust.score", score(ie, 0.3), 5))])
    await indexer(FakeSource(chain), store).sync()
    verdicts = [(await msg(store, chain.block_id(i, n)))["verdict"]
                for i, n in ((1, 0), (1, 1), (2, 0), (2, 1), (2, 2))]
    assert verdicts == ["PRODUCER_SIGNED", "PRODUCER_SIGNED", "REPLAY", "REPLAY",
                        "PRODUCER_SIGNED"]


async def test_default_policy_refuses_unlisted_signers(store: Store):
    chain = FakeChain()
    chain.add([("trust.score", signed(ALICE, "trust.score", score("D:aabbccddeeff", 0.5), 1)),
               ("trust.score", json.dumps(score("D:aabbccddeeff", 0.5)).encode())])
    await Indexer(FakeSource(chain), store).sync()
    assert [(await msg(store, chain.block_id(1, n)))["verdict"] for n in (0, 1)] == [
        "UNAUTHORIZED_WRITER", "UNSIGNED_LEGACY"]
    assert (await store.stats())["policy"] == "none"


class RecordingResolver:
    def __init__(self, store: Store, fail: int = 0) -> None:
        self.store = store
        self.fail = fail
        self.calls: list[tuple[str, int | None]] = []
        self.inner = OfflineResolver()

    async def aresolve_kid(self, kid: str, at_ms: int | None):
        assert self.store._pinned() is None, "resolver called inside the milestone transaction"
        self.calls.append((kid, at_ms))
        if self.fail:
            self.fail -= 1
            raise ConnectionError("resolver down")
        return self.inner(kid)


def kid_of(sk: Ed25519PrivateKey) -> str:
    did = did_key(sk)
    return f"{did}#{did[len('did:key:'):]}"


async def test_keys_resolved_before_the_transaction_at_milestone_time(store: Store):
    ie = "D:aabbccddeeff"
    chain = FakeChain()
    chain.add([("trust.score", signed(ALICE, "trust.score", score(ie, 0.5), 1)),
               ("trust.score", signed(ALICE, "trust.score", score(ie, 0.6), 2)),
               ("trust.score", signed(BOB, "trust.score", score(ie, 0.6), 1)),
               ("trust.score", json.dumps(score(ie, 0.5)).encode())])
    res = RecordingResolver(store)
    await indexer(FakeSource(chain), store, resolve=res).sync()
    at = chain.ms[1].timestamp * 1000
    assert sorted(res.calls) == sorted([(kid_of(ALICE), at), (kid_of(BOB), at)])
    assert [(await msg(store, chain.block_id(1, n)))["verdict"] for n in range(3)] == [
        "PRODUCER_SIGNED", "PRODUCER_SIGNED", "UNAUTHORIZED_WRITER"]


async def test_resolver_outage_retries_instead_of_forging(store: Store):
    chain = FakeChain()
    chain.add([("trust.score", signed(ALICE, "trust.score", score("D:aabbccddeeff", 0.5), 1))])
    res = RecordingResolver(store, fail=3)
    seen = []

    async def sleep(_s):
        st = await store.stats()
        seen.append((st.get("resolver"), st.get("indexer"), st["messages"]))
        await asyncio.sleep(0)

    ix = indexer(FakeSource(chain, tail=True), store, resolve=res, sleep=sleep)
    task = asyncio.create_task(ix.run())
    await wait_cursor(store, 1)
    await ix.stop()
    await task
    assert seen == [("unreachable", "retrying (resolver unreachable)", 0)] * 3
    assert (await msg(store, chain.block_id(1, 0)))["verdict"] == "PRODUCER_SIGNED"
    st = await store.stats()
    assert (st["resolver"], st["indexer"]) == ("ok", "ok")


async def test_plain_callable_resolver_still_works(store: Store):
    chain = FakeChain()
    chain.add([("trust.score", signed(ALICE, "trust.score", score("D:aabbccddeeff", 0.5), 1))])
    offline = OfflineResolver()
    await indexer(FakeSource(chain), store, resolve=lambda kid: offline(kid)).sync()
    assert (await msg(store, chain.block_id(1, 0)))["verdict"] == "PRODUCER_SIGNED"


def nested(depth: int) -> dict:
    obj: dict = {"leaf": True}
    for _ in range(depth - 1):
        obj = {"n": obj}
    return obj


async def test_hostile_nesting_is_indexed(store: Store):
    deep_body = "{" + '"a":{' * 1199 + '"b":1' + "}" * 1199 + "}"  # 1200 levels
    shell = json.loads(signed(ALICE, "trust.score", {"x": 1}, 1))
    shell.pop("body")
    deep_env = (json.dumps(shell)[:-1] + ', "body": ' + deep_body + "}").encode()
    payloads = [
        ("trust.score", deep_env),
        ("LLO-K8s", b"[" * 2990 + b"]" * 2990),
        ("deep.legacy", json.dumps(nested(100)).encode()),
        # A tag without a schema, so only the nesting decides.
        ("deep.signed", signed(ALICE, "deep.signed", nested(63), 2)),  # 64 levels in all
        ("deep.signed", signed(ALICE, "deep.signed", nested(64), 3)),  # 65 levels
    ]
    chain = FakeChain()
    chain.add(payloads)
    await indexer(FakeSource(chain), store).sync()
    rows = [await msg(store, chain.block_id(1, n)) for n in range(len(payloads))]
    for (_, data), row in zip(payloads, rows, strict=True):
        assert row["data"] == data
    assert [r["verdict"] for r in rows] == [
        "MALFORMED", "MALFORMED", "UNSIGNED_LEGACY", "PRODUCER_SIGNED", "MALFORMED"]
    for r in (rows[0], rows[1], rows[2], rows[4]):
        assert r["json"] is None and r["canon_hash"] is None
    assert rows[1]["kind"] == "unknown"
    assert rows[3]["json"] == nested(63)
    reasons = {e["payload"]["blockId"]: e["payload"]["reason"]
               for e in await store.events_after(0, 100) if e["type"] == "message"}
    assert reasons["0x" + chain.block_id(1, 0).hex()] == "nesting too deep"
    assert reasons["0x" + chain.block_id(1, 4).hex()] == "nesting too deep"
    assert await store.get_cursor() == 1


def _over_cap(n: int, *, closed: bool = True) -> bytes:
    """An object nesting `n` containers in all (json.loads parses 2501 on every platform)."""
    return b'{"a":' + b"[" * (n - 1) + ((b"]" * (n - 1) + b"}") if closed else b"")


async def test_payloads_past_the_shared_cap_are_malformed(store: Store):
    """Past witness_core.nesting.MAX_JSON_DEPTH (2500) a payload is MALFORMED "nesting too
    deep" whatever its tag, envelope or not, valid JSON or not; at the cap it is read."""
    shell = json.loads(signed(ALICE, "trust.score", {"x": 1}, 1))
    shell.pop("body")
    deep_env = (json.dumps(shell)[:-1] + ', "body": {"a":' + "[" * 2499 + "]" * 2499
                + "}}").encode()  # 2501 levels in all
    payloads = [
        ("deep.legacy", _over_cap(2500)),
        ("deep.legacy", _over_cap(2501)),
        ("trust.score", _over_cap(2501)),
        ("deep.legacy", _over_cap(2501, closed=False)),
        ("trust.score", deep_env),
    ]
    chain = FakeChain()
    chain.add(payloads)
    await indexer(FakeSource(chain), store).sync()
    rows = [await msg(store, chain.block_id(1, n)) for n in range(len(payloads))]
    assert [r["verdict"] for r in rows] == ["UNSIGNED_LEGACY"] + ["MALFORMED"] * 4
    assert all(r["json"] is None and r["kind"] == "unknown" for r in rows[1:])
    reasons = {e["payload"]["blockId"]: e["payload"]["reason"]
               for e in await store.events_after(0, 100) if e["type"] == "message"}
    for n in range(1, len(payloads)):
        assert reasons["0x" + chain.block_id(1, n).hex()] == "nesting too deep", n


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


async def test_relay_sealed_legacy_report_is_attested_and_findable(store: Store):
    """What the relay writes for a legacy audit.report on an encrypted tag: sealed to the
    domain's key-agreement key with a blind token for the tag. Stored with its ciphertext
    only, RELAY_ATTESTED (a sealed body is not judged on its schema), and found by the token
    computed with the domain's search key."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from witness_core import sealed

    domain_kex = X25519PrivateKey.generate()
    recipient = sealed.Recipient("did:example:domain#kex-1",
                                 domain_kex.public_key().public_bytes_raw())
    search_key = b"k" * 32
    plaintext = {"reportId": "r-1", "secret": "s0123456789abcdef"}  # not an audit.report shape
    token = sealed.blind_token(search_key, "tag", "audit.report")
    did = did_key(RELAY)
    env = envelope.seal("audit.report", None, iss=did, kid=kid_of(RELAY), sign_key=RELAY,
                        seq=1, att_mode="relay", att_sub="anonymous",
                        enc=sealed.encrypt_body(plaintext, [recipient]), bix=[token])
    chain = FakeChain()
    chain.add([("audit.report", canon.jcs(env))])
    pol = policy.load({"version": 1, "tags": {"audit.report": {
        "allowed": [did], "require_signature": False, "legacy_grace": True}}})
    await indexer(FakeSource(chain), store, policy=pol).sync()

    bid = chain.block_id(1, 0)
    row = await msg(store, bid)
    assert (row["verdict"], row["encrypted"], row["json"]) == ("RELAY_ATTESTED", True, None)
    stored = json.loads(row["data"])
    assert "body" not in stored and isinstance(stored["enc"], dict)
    assert b"s0123456789abcdef" not in row["data"] and b"r-1" not in row["data"]
    with pytest.raises((sealed.NotARecipient, sealed.DecryptError)):
        sealed.decrypt_body(stored["enc"], "did:none#kex-1", X25519PrivateKey.generate())
    assert sealed.decrypt_body(stored["enc"], recipient.kid, domain_kex) == plaintext
    assert [bytes(r["block_id"]) for r in await store.lookup_blind([token])] == [bid]


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
        # Signed, on a tag without a schema: the body is fine, only unstorable.
        ("nul.signed", signed(ALICE, "nul.signed", {"id": "D:aabbccddeeff",
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


# -- the Task 9 DID resolver -------------------------------------------------------------------

ANCHOR = "http://anchor.test"
IOTA_DID = "did:iota:testnet:0x" + "ab" * 32
IOTA_KEY = Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)


def iota_signed(seq: int) -> bytes:
    env = envelope.seal("trust.score", score("D:aabbccddeeff", 0.5), iss=IOTA_DID,
                        kid=IOTA_DID + "#sig-1", sign_key=IOTA_KEY, seq=seq,
                        att_mode="producer", now_ms=1_790_000_000_000 + seq,
                        nonce=seq.to_bytes(16, "big"))
    return json.dumps(env).encode()


def did_reply(revoked_at_ms: int | None) -> dict:
    return {"doc": {"id": IOTA_DID}, "version": "3", "historyComplete": True,
            "keys": [{"kid": "#sig-1", "type": "Ed25519",
                      "publicKeyHex": IOTA_KEY.public_key().public_bytes_raw().hex(),
                      "revokedAtMs": revoked_at_ms}]}


async def test_did_resolver_is_asked_at_the_milestone_time(store: Store):
    chain = FakeChain()
    chain.add([("trust.score", iota_signed(1))])
    chain.add([("trust.score", iota_signed(2)),
               ("trust.score", signed(ALICE, "trust.score", score("D:aabbccddeeff", 0.5), 1))])
    revoked = chain.ms[2].timestamp * 1000 - 1  # between the two milestones
    url = f"{ANCHOR}/resolve/{quote(IOTA_DID, safe='')}"
    async with respx.mock(assert_all_called=True) as router:
        route = router.get(url).mock(return_value=httpx.Response(200, json=did_reply(revoked)))
        resolver = DidResolver(ANCHOR)
        await indexer(FakeSource(chain), store, resolve=resolver, policy=ALLOW_ALL).sync()
        await resolver.aclose()
    assert route.call_count == 1  # cached across milestones; did:key needs no call
    assert [(await msg(store, chain.block_id(i, 0)))["verdict"] for i in (1, 2)] == [
        "PRODUCER_SIGNED", "REVOKED_KEY"]
    assert (await msg(store, chain.block_id(2, 1)))["verdict"] == "PRODUCER_SIGNED"


async def test_revoked_key_wins_over_the_writer_policy(store: Store):
    """A key the DID revoked signs for nobody: REVOKED_KEY whether or not the policy lists
    the DID (as the relay's gate and the bundle's envelope step decide). Before the
    revocation the same unlisted signer is an UNAUTHORIZED_WRITER."""
    chain = FakeChain()
    chain.add([("trust.score", iota_signed(1))])
    chain.add([("trust.score", iota_signed(2)),
               ("trust.score", signed(BOB, "trust.score", score("D:aabbccddeeff", 0.5), 1))])
    revoked = chain.ms[2].timestamp * 1000 - 1
    url = f"{ANCHOR}/resolve/{quote(IOTA_DID, safe='')}"
    rules = RulesEngine(store, None, DidResolver(None), POLICY)
    async with respx.mock(assert_all_called=False) as router:
        router.get(url).mock(return_value=httpx.Response(200, json=did_reply(revoked)))
        resolver = DidResolver(ANCHOR)
        await indexer(FakeSource(chain), store, resolve=resolver, rules=rules).sync()
        await resolver.aclose()
    assert IOTA_DID not in POLICY.tags["trust.score"].allowed
    assert [(await msg(store, chain.block_id(*at)))["verdict"] for at in ((1, 0), (2, 0), (2, 1))
            ] == ["UNAUTHORIZED_WRITER", "REVOKED_KEY", "UNAUTHORIZED_WRITER"]
    revoked_row = await msg(store, chain.block_id(2, 0))
    assert (revoked_row["iss"], revoked_row["seq"]) == (IOTA_DID, 2)
    assert [a["rule"] for a in await store.alerts({"block_id": chain.block_id(2, 0)})] == [
        "REVOKED_KEY"]


async def test_non_canonical_did_is_forged_without_a_lookup(store: Store):
    """An upper-case or short did:iota DID is FORGED "non-canonical DID": the resolver is
    never asked (the anchor would answer for the canonical spelling, which no reply for this
    one can match), so the milestone cannot stall on it."""
    ie = "D:aabbccddeeff"
    payloads = []
    for n, did in enumerate(("did:iota:testnet:0x" + "AB" * 32, "did:iota:testnet:0xabc"), 1):
        env = envelope.seal("trust.score", score(ie, 0.5), iss=did, kid=did + "#sig-1",
                            sign_key=IOTA_KEY, seq=n, att_mode="producer",
                            now_ms=1_790_000_000_000 + n, nonce=n.to_bytes(16, "big"))
        payloads.append(("trust.score", json.dumps(env).encode()))
    chain = FakeChain()
    chain.add(payloads)
    async with respx.mock(assert_all_called=False) as router:
        route = router.get(url__startswith=ANCHOR).mock(return_value=httpx.Response(503))
        resolver = DidResolver(ANCHOR)
        await indexer(FakeSource(chain), store, resolve=resolver, policy=ALLOW_ALL).sync()
        await resolver.aclose()
    assert route.call_count == 0
    assert [(await msg(store, chain.block_id(1, n)))["verdict"] for n in (0, 1)] == [
        "FORGED", "FORGED"]
    reasons = {e["payload"]["blockId"]: e["payload"]["reason"]
               for e in await store.events_after(0, 100) if e["type"] == "message"}
    for n in (0, 1):
        assert reasons["0x" + chain.block_id(1, n).hex()] == "non-canonical DID"
    assert await store.get_cursor() == 1


async def test_hostile_did_document_forges_instead_of_stalling(store: Store):
    """A did:iota document nested 600 levels deep is unusable: its signer is FORGED and
    the milestone is indexed, never stuck on the resolver."""
    chain = FakeChain()
    chain.add([("trust.score", iota_signed(1))])
    deep: object = "leaf"
    for _ in range(600):
        deep = {"n": deep}
    doc = did_reply(None)
    doc["doc"]["x"] = deep
    url = f"{ANCHOR}/resolve/{quote(IOTA_DID, safe='')}"
    async with respx.mock() as router:
        router.get(url).mock(return_value=httpx.Response(200, json=doc))
        resolver = DidResolver(ANCHOR)
        await indexer(FakeSource(chain), store, resolve=resolver, policy=ALLOW_ALL).sync()
        await resolver.aclose()
    assert (await msg(store, chain.block_id(1, 0)))["verdict"] == "FORGED"
    assert await store.get_cursor() == 1


@pytest.mark.parametrize("failure", [httpx.ConnectError("refused"), httpx.Response(503),
                                     httpx.Response(429), httpx.ReadTimeout("slow"),
                                     httpx.Response(401), httpx.Response(403),
                                     httpx.Response(407)])
async def test_unreachable_did_resolver_stalls_the_milestone(store: Store, failure):
    chain = FakeChain()
    chain.add([("trust.score", iota_signed(1))])
    url = f"{ANCHOR}/resolve/{quote(IOTA_DID, safe='')}"
    async with respx.mock() as router:
        route = router.get(url)
        if isinstance(failure, httpx.Response):
            route.mock(return_value=failure)
        else:
            route.mock(side_effect=failure)
        resolver = DidResolver(ANCHOR)
        with pytest.raises(ResolverFailed) as caught:
            await indexer(FakeSource(chain), store, resolve=resolver, policy=ALLOW_ALL).sync()
        await resolver.aclose()
    assert caught.value.kid == IOTA_DID + "#sig-1"
    assert resolver.status == "unreachable"
    stats = await store.stats()
    assert (stats["milestones"], stats["messages"], stats["cursor"]) == (0, 0, 0)


async def test_disabled_did_resolution_forges_instead_of_stalling(store: Store):
    chain = FakeChain()
    chain.add([("trust.score", iota_signed(1)),
               ("trust.score", signed(ALICE, "trust.score", score("D:aabbccddeeff", 0.5), 1))])
    await indexer(FakeSource(chain), store, resolve=DidResolver(None), policy=ALLOW_ALL).sync()
    assert [(await msg(store, chain.block_id(1, n)))["verdict"] for n in (0, 1)] == [
        "FORGED", "PRODUCER_SIGNED"]  # did:key still needs no registry
    assert (await store.stats())["resolver"] == "disabled"


async def test_unknown_did_is_forged(store: Store):
    chain = FakeChain()
    chain.add([("trust.score", iota_signed(1))])
    url = f"{ANCHOR}/resolve/{quote(IOTA_DID, safe='')}"
    async with respx.mock() as router:
        router.get(url).mock(return_value=httpx.Response(404, json={"error": "not found"}))
        resolver = DidResolver(ANCHOR)
        await indexer(FakeSource(chain), store, resolve=resolver, policy=ALLOW_ALL).sync()
        await resolver.aclose()
    assert (await msg(store, chain.block_id(1, 0)))["verdict"] == "FORGED"


async def test_oversized_did_is_forged_without_asking(store: Store):
    huge = "did:iota:" + ":" * 6000
    env = envelope.seal("trust.score", score("D:aabbccddeeff", 0.5), iss=huge,
                        kid=huge + "#sig-1", sign_key=IOTA_KEY, seq=1, att_mode="producer",
                        now_ms=1, nonce=b"h" * 16)
    chain = FakeChain()
    chain.add([("trust.score", json.dumps(env).encode()),
               ("trust.score", json.dumps(score("D:aabbccddeeff", 0.5)).encode())])
    async with respx.mock(assert_all_called=False) as router:
        route = router.get(url__startswith=ANCHOR).mock(return_value=httpx.Response(431))
        resolver = DidResolver(ANCHOR)
        await indexer(FakeSource(chain), store, resolve=resolver, policy=ALLOW_ALL).sync()
        await resolver.aclose()
    assert route.call_count == 0
    assert [(await msg(store, chain.block_id(1, n)))["verdict"] for n in (0, 1)] == [
        "FORGED", "UNSIGNED_LEGACY"]
    assert await store.get_cursor() == 1


async def test_only_checkable_envelopes_are_resolved(store: Store):
    ie = "D:aabbccddeeff"
    bad_seq = json.loads(signed(ALICE, "trust.score", score(ie, 0.5), 2))
    bad_seq["seq"] = -1
    other_kid = json.loads(signed(ALICE, "trust.score", score(ie, 0.5), 3))
    other_kid["kid"] = kid_of(BOB)
    chain = FakeChain()
    chain.add([("LLO-K8s", signed(ALICE, "trust.score", score(ie, 0.5), 1)),  # tag mismatch
               ("trust.score", json.dumps(bad_seq).encode()),                 # malformed
               ("trust.score", json.dumps(other_kid).encode())])              # kid of iss?
    res = RecordingResolver(store)
    await indexer(FakeSource(chain), store, resolve=res).sync()
    assert res.calls == []
    assert [(await msg(store, chain.block_id(1, n)))["verdict"] for n in range(3)] == [
        "FORGED", "MALFORMED", "FORGED"]


async def test_resolver_failing_on_one_key_is_reported_stuck(store: Store):
    chain = FakeChain()
    chain.add([("trust.score", signed(ALICE, "trust.score", score("D:aabbccddeeff", 0.5), 1))])
    res = RecordingResolver(store, fail=10_000)
    seen = []

    async def sleep(_s):
        st = await store.stats()
        seen.append((st.get("indexer"), st.get("resolver")))
        await asyncio.sleep(0)

    ix = indexer(FakeSource(chain, tail=True), store, resolve=res, sleep=sleep)
    task = asyncio.create_task(ix.run())
    while len(seen) < 6:
        await asyncio.sleep(0.01)
    await ix.stop()
    await task
    stuck = f"stuck at 1 (resolver: {kid_of(ALICE)[:64]})"
    assert seen[:6] == [("retrying (resolver unreachable)", "unreachable")] * 4 + [
        (stuck, "unreachable")] * 2
    assert (await store.stats())["messages"] == 0


async def test_allow_all_policy_is_labelled_for_library_callers(store: Store):
    chain = FakeChain()
    chain.add([("x", b"{}")])
    await Indexer(FakeSource(chain), store, policy=ALLOW_ALL).sync()
    assert (await store.stats())["policy"] == "allow-any"


async def test_rules_engine_alerts_are_stored_and_emitted_once(store: Store):
    chain = FakeChain()
    chain.add([("trust.score", signed(BOB, "trust.score", score("D:aabbccddeeff", 0.1), 1))])
    rules = RulesEngine(store, None, DidResolver(None), POLICY)
    ix = indexer(FakeSource(chain), store, rules=rules)
    await ix.sync()
    await ix.process_milestone(chain.ms[1])
    assert [a["rule"] for a in await store.alerts()] == ["UNAUTHORIZED_WRITER"]
    assert (await event_types(store)).count("alert") == 1
