import itertools
import random
from urllib.parse import quote

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_core import canon, checkpoint, envelope, merkle, schema
from witness_core import policy as writer_policy
from witness_core import verdicts as V
from witness_core.ids import blake2b256, to_hex
from witness_indexer.anchor_client import AnchorClient
from witness_indexer.orion import OrionClient
from witness_indexer.resolver import DidResolver
from witness_indexer.rules import SEVERITY, RulesConfig, RulesEngine
from witness_indexer.store import MessageRow, Store, Submission

ORION = "http://orion.test"
ANCHOR = "http://anchor.test"
ENTITIES = f"{ORION}/ngsi-ld/v1/entities"
URN = "urn:ngsi-ld:InfrastructureElement:"
TM = "did:iota:testnet:0x7151"
TM_KEY = Ed25519PrivateKey.from_private_bytes(b"\x41" * 32)
SO = "did:iota:testnet:0x5050"
SO_KEY = Ed25519PrivateKey.from_private_bytes(b"\x42" * 32)
ATTACKER = Ed25519PrivateKey.from_private_bytes(b"\x43" * 32)
IE = "MyDomain:fa163e5e25ef"
T0 = 1_791_280_000  # milestone timestamp, seconds
POLICY = writer_policy.load({
    "version": 3,
    "tags": {
        "trust.score": {"allowed": [TM], "require_signature": True, "legacy_grace": False},
        "self-orchestrator": {"allowed": ["*"], "require_signature": False, "legacy_grace": True},
    },
    "default": {"allowed": ["*"], "require_signature": False, "legacy_grace": True},
})
_blocks = itertools.count(1)


def reply(did: str, key: Ed25519PrivateKey, revoked: int | None = None) -> dict:
    entry = {"kid": "#sig-1", "type": "Ed25519",
             "publicKeyHex": key.public_key().public_bytes_raw().hex(), "revokedAtMs": revoked}
    return {"doc": {"id": did}, "version": "1", "keys": [entry], "historyComplete": True}


def message(tag: str, obj: dict, *, verdict: str, ms: int, ts: int) -> MessageRow:
    """The row the verdict pipeline stores for one tagged-data block."""
    data = canon.jcs(obj)
    c = schema.classify(tag, data)
    env = c.envelope or {}
    return MessageRow(
        block_id=blake2b256(data + next(_blocks).to_bytes(8, "big")), tag=tag, kind=c.kind,
        data=data, json=c.json, ie_id=c.ie_id, canon_hash=canon.canon_hash(obj),
        iss=env.get("iss"), kid=env.get("kid"), seq=env.get("seq"), iat=env.get("iat"),
        verdict=verdict, ms_index=ms, wf_index=0, ts=ts,
        prev=bytes.fromhex(c.prev[2:]) if c.prev else None, corr=c.corr, nonce=c.nonce)


class Writer:
    """One signing component: keeps its seq counter and `prev` chain like the SDK does."""

    def __init__(self, iss: str = TM, key: Ed25519PrivateKey = TM_KEY) -> None:
        self.iss, self.key = iss, key
        self.seq = 0
        self.head: bytes | None = None

    def signed(self, body: dict, *, ms: int, ts: int, tag: str = "trust.score",
               verdict: str = V.PRODUCER_SIGNED, iat: int | None = None, seq: int | None = None,
               prev: object = "chain", key: Ed25519PrivateKey | None = None,
               nonce: bytes | None = None) -> MessageRow:
        seq = self.seq + 1 if seq is None else seq
        head = self.head if prev == "chain" else prev
        env = envelope.seal(
            tag, body, iss=self.iss, kid=self.iss + "#sig-1", sign_key=key or self.key, seq=seq,
            att_mode="producer", now_ms=ts * 1000 - 1500 if iat is None else iat, nonce=nonce,
            prev=None if head is None else to_hex(head))
        row = message(tag, env, verdict=verdict, ms=ms, ts=ts)
        if verdict == V.PRODUCER_SIGNED:
            self.seq, self.head = max(self.seq, seq), row.block_id
        return row

    def score(self, score: float, *, ms: int, ts: int, ie: str = IE, **kw) -> MessageRow:
        return self.signed({"score": score, "id": ie}, ms=ms, ts=ts, **kw)


class Orion:
    def __init__(self, respx_mock) -> None:
        self.scores: dict[str, float | None] = {IE: 0.8}
        self.down = False
        respx_mock.get(ENTITIES).mock(side_effect=self._answer)

    def _answer(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("refused")
        return httpx.Response(200, json=[
            {"id": URN + ie, "type": "InfrastructureElement",
             **({} if s is None else {"trustScore": {"type": "Property", "value": s}})}
            for ie, s in self.scores.items()])


class Clock:
    def __init__(self, ms: int) -> None:
        self.ms = ms

    def __call__(self) -> int:
        return self.ms


@pytest.fixture
def orion(respx_mock) -> Orion:
    return Orion(respx_mock)


@pytest.fixture
def make_engine(store: Store, orion: Orion):
    def make(resolver: DidResolver | None = None, **cfg) -> RulesEngine:
        resolver = resolver or DidResolver(None, offline_docs={
            TM: reply(TM, TM_KEY), SO: reply(SO, SO_KEY)})
        return RulesEngine(store, OrionClient(ORION), resolver, POLICY, RulesConfig(**cfg),
                           anchor=AnchorClient(ANCHOR), now_ms=Clock(T0 * 1000))
    return make


@pytest.fixture
def engine(make_engine) -> RulesEngine:
    return make_engine()


async def ingest(engine: RulesEngine, row: MessageRow) -> list[str]:
    await engine.store.put_message(row)
    return [a.rule for a in await engine.on_message(row)]


async def fired(engine: RulesEngine, row: MessageRow) -> list:
    await engine.store.put_message(row)
    return await engine.on_message(row)


def at(minute: int) -> dict:
    """Milestone index and timestamp of a block confirmed `minute` minutes after T0."""
    return {"ms": 100 + minute, "ts": T0 + 60 * minute}


# ---------------------------------------------------------------- per-message rules


async def test_r1_forged(engine):
    row = Writer().score(0.8, key=ATTACKER, verdict=V.FORGED, **at(0))
    [a] = await fired(engine, row)
    # The IE is the one the message claims to be about, so the IE's history shows the attack.
    assert (a.rule, a.severity, a.block_id, a.ie_id) == ("FORGED", "critical", row.block_id, IE)
    assert a.evidence["kid"] == TM + "#sig-1"
    assert "signature does not verify" in a.evidence["reason"]
    assert await engine.store.has_alert("FORGED", block_id=row.block_id)


async def test_r1_forged_tag_mismatch_reason(engine):
    w = Writer()
    row = w.score(0.8, verdict=V.FORGED, **at(0))
    row.tag = "LLO-K8s"  # envelope says trust.score, the block tag says otherwise
    [a] = await fired(engine, row)
    assert a.evidence["reason"] == "envelope tag does not match block tag"


async def test_r2_unauthorized_writer(engine):
    row = Writer(SO, SO_KEY).score(0.8, verdict=V.UNAUTHORIZED_WRITER, **at(0))
    [a] = await fired(engine, row)
    assert (a.rule, a.severity) == ("UNAUTHORIZED_WRITER", "high")
    assert a.evidence["iss"] == SO and a.evidence["allowed"] == [TM]
    assert a.evidence["policyVersion"] == 3


async def test_r3_replay(engine):
    w = Writer()
    original = w.score(0.8, nonce=b"\x01" * 16, **at(0))
    assert await ingest(engine, original) == []
    copy = message("trust.score", envelope.seal(
        "trust.score", {"score": 0.8, "id": IE}, iss=TM, kid=TM + "#sig-1", sign_key=TM_KEY,
        seq=1, att_mode="producer", now_ms=original.iat, nonce=b"\x01" * 16), verdict=V.REPLAY,
        **at(1))
    [a] = await fired(engine, copy)
    assert (a.rule, a.severity) == ("REPLAY", "high")
    reasons = " | ".join(a.evidence["reasons"])
    assert "seq 1 is not above the last accepted seq 1" in reasons
    assert "nonce already used" in reasons
    assert to_hex(original.block_id) in reasons


async def test_r4_unsigned_on_signature_required_tag(engine):
    row = message("trust.score", {"score": 0.8, "id": IE}, verdict=V.UNSIGNED_LEGACY, **at(0))
    [a] = await fired(engine, row)
    assert (a.rule, a.severity, a.ie_id) == ("UNSIGNED", "medium", IE)
    # Unsigned is fine where the policy tolerates legacy writers.
    so = message("self-orchestrator", {"infrastructureElementId": URN + IE, "errorCode": "E7"},
                 verdict=V.UNSIGNED_LEGACY, **at(1))
    assert await ingest(engine, so) == []


async def test_r6_unknown_ie_once_per_ie(engine):
    w = Writer()
    first = w.score(0.8, ie="MyDomain:0000000000aa", **at(0))
    [a] = await fired(engine, first)
    assert (a.rule, a.severity, a.ie_id) == ("UNKNOWN_IE", "low", "MyDomain:0000000000aa")
    assert a.block_id == first.block_id
    assert await ingest(engine, w.score(0.81, ie="MyDomain:0000000000aa", **at(1))) == []


async def test_r7_anomaly(engine):
    w = Writer()
    assert await ingest(engine, w.score(0.8, **at(0))) == []
    [a] = await fired(engine, w.score(0.3, **at(1)))
    assert (a.rule, a.severity, a.ie_id) == ("ANOMALY", "medium", IE)
    assert a.evidence["previousScore"] == 0.8 and a.evidence["score"] == 0.3
    assert a.evidence["delta"] == pytest.approx(-0.5)


async def test_anomaly_corroborated(engine):
    w = Writer()
    assert await ingest(engine, w.score(0.8, **at(0))) == []
    so = message("self-orchestrator", {"infrastructureElementId": URN + IE, "errorCode": "E7"},
                 verdict=V.UNSIGNED_LEGACY, ms=101, ts=T0 + 50)
    assert await ingest(engine, so) == []
    assert await ingest(engine, w.score(0.3, **at(1))) == []
    # A security event long before the drop does not explain it.
    assert await ingest(engine, w.score(0.8, **at(2))) == []  # +0.5 within window of E7
    assert await ingest(engine, w.score(0.3, **at(20))) == ["ANOMALY"]


async def test_r9_malformed(engine):
    row = message("trust.score", {"w": 1, "tag": "trust.score", "sig": "x"},
                  verdict=V.MALFORMED, **at(0))
    [a] = await fired(engine, row)
    assert (a.rule, a.severity) == ("MALFORMED", "low")
    assert a.evidence["reason"] == "missing or invalid field: iss"
    legacy = message("trust.score", {"score": 7, "id": IE}, verdict=V.MALFORMED, **at(1))
    [b] = await fired(engine, legacy)
    assert b.evidence["reason"] == "body does not match the trust.score schema"


async def test_r10_revoked_key(make_engine):
    revoked_at = (T0 + 30) * 1000
    engine = make_engine(DidResolver(None, offline_docs={TM: reply(TM, TM_KEY, revoked_at)}))
    row = Writer().score(0.8, verdict=V.REVOKED_KEY, **at(1))
    [a] = await fired(engine, row)
    assert (a.rule, a.severity) == ("REVOKED_KEY", "high")
    assert a.evidence["revokedAtMs"] == revoked_at
    assert a.evidence["includedAtMs"] == (T0 + 60) * 1000


async def test_resolver_unreachable_changes_no_verdict(make_engine, respx_mock, store):
    respx_mock.get(f"{ANCHOR}/resolve/{quote(TM, safe='')}").mock(
        side_effect=httpx.ConnectError("refused"))
    engine = make_engine(DidResolver(ANCHOR))
    row = Writer().score(0.8, verdict=V.REVOKED_KEY, **at(1))
    [a] = await fired(engine, row)
    assert a.rule == "REVOKED_KEY" and a.evidence["revokedAtMs"] is None
    assert "resolver unavailable" in a.evidence["note"]
    assert (await store.get_message(row.block_id))["verdict"] == V.REVOKED_KEY
    assert (await store.stats())["resolver"] == "unreachable"


async def test_r12_clock_skew(engine):
    row = Writer().score(0.8, iat=(T0 + 600) * 1000, **at(0))
    [a] = await fired(engine, row)
    assert (a.rule, a.severity) == ("CLOCK_SKEW", "low")
    assert a.evidence["skewS"] == 600


async def test_r15_chain_gap(engine):
    w = Writer()
    for m in range(2):
        assert await ingest(engine, w.score(0.8, **at(m))) == []
    head, lost = w.head, blake2b256(b"never indexed")
    row = w.score(0.8, seq=4, prev=lost, **at(3))
    [a] = await fired(engine, row)
    assert (a.rule, a.severity) == ("CHAIN_GAP", "medium")
    assert (a.evidence["prev"], a.evidence["expectedPrev"]) == (to_hex(lost), to_hex(head))


async def test_r16_chain_fork(engine):
    w = Writer()
    first = w.score(0.8, **at(0))
    assert await ingest(engine, first) == []
    second = w.score(0.8, **at(1))
    assert await ingest(engine, second) == []
    fork = w.score(0.8, prev=first.block_id, **at(2))
    [a] = await fired(engine, fork)
    assert (a.rule, a.severity) == ("CHAIN_FORK", "high")
    assert a.evidence["siblings"] == [to_hex(second.block_id)]


async def test_bad_verdicts_skip_content_rules(engine):
    """A forged message about an unknown IE with a wild score is FORGED, nothing more."""
    w = Writer()
    assert await ingest(engine, w.score(0.9, **at(0))) == []
    row = w.score(0.0, ie="MyDomain:0000000000bb", key=ATTACKER, verdict=V.FORGED,
                  iat=(T0 + 9000) * 1000, **at(1))
    assert await ingest(engine, row) == ["FORGED"]


# ---------------------------------------------------------------- periodic rules


async def test_r5_drift_grace(make_engine, orion):
    engine = make_engine(score_interval_s=3600)
    assert await ingest(engine, Writer().score(0.8, **at(0))) == []
    orion.scores[IE] = 0.5
    start = (T0 + 10) * 1000
    assert await engine.periodic(start) == []
    assert await engine.periodic(start + 100_000) == []
    [a] = await engine.periodic(start + 151_000)
    assert (a.rule, a.severity, a.ie_id) == ("DRIFT", "medium", IE)
    assert (a.evidence["orionTrustScore"], a.evidence["ledgerScore"]) == (0.5, 0.8)
    assert await engine.periodic(start + 200_000) == []  # once per episode
    orion.scores[IE] = 0.805  # within epsilon: the episode ends
    assert await engine.periodic(start + 210_000) == []
    orion.scores[IE] = 0.5
    assert await engine.periodic(start + 220_000) == []
    assert [a.rule for a in await engine.periodic(start + 372_000)] == ["DRIFT"]


async def test_drift_suppressed_when_orion_down(make_engine, orion, store):
    engine = make_engine(score_interval_s=3600)
    assert await ingest(engine, Writer().score(0.8, **at(0))) == []
    orion.scores[IE] = 0.5
    orion.down = True
    start = (T0 + 10) * 1000
    for dt in (0, 200_000, 400_000):
        assert await engine.periodic(start + dt) == []
    assert (await store.stats())["orion"] == "unreachable"
    # Back up: the divergence is timed from when Orion could be seen again.
    orion.down = False
    assert await engine.periodic(start + 500_000) == []
    assert (await store.stats())["orion"] == "ok"
    assert [a.rule for a in await engine.periodic(start + 651_000)] == ["DRIFT"]


async def test_unknown_ie_needs_orion(engine, orion, store):
    orion.down = True
    assert await ingest(engine, Writer().score(0.8, ie="MyDomain:0000000000cc", **at(0))) == []
    assert (await store.stats())["orion"] == "unreachable"


async def test_r8_stale_once_per_window(engine):
    w = Writer()
    assert await ingest(engine, w.score(0.8, **at(0))) == []
    assert await engine.periodic((T0 + 100) * 1000) == []
    [a] = await engine.periodic((T0 + 121) * 1000)
    assert (a.rule, a.severity, a.ie_id) == ("STALE", "low", IE)
    assert a.dedupe_key == f"window:{T0}+120"
    assert await engine.periodic((T0 + 500) * 1000) == []
    # A new score ends the silence; the next one is a new window.
    assert await ingest(engine, w.score(0.8, **at(10))) == []
    assert [a.rule for a in await engine.periodic((T0 + 600 + 121) * 1000)] == ["STALE"]


async def _anchor_fixture(store: Store, respx_mock, *, rewrite: bool = False,
                          mirror_hash: bytes | None = None):
    ids = [blake2b256(bytes([i])) for i in range(10, 14)]
    cp = checkpoint.build("private_tangle1", "MyDomain", (10, ids[0]), (13, ids[-1]), ids, 5,
                          b"\x11" * 32, None)
    stored = list(ids)
    if rewrite:
        stored[2] = blake2b256(b"rewritten milestone 12")
    for i, mid in enumerate(stored):
        await store.put_milestone(10 + i, mid, T0 + i, b"e", [], b"\0" * 32, b"\0" * 32)
    await store.put_anchor(seq=1, from_ms=10, to_ms=13, ms_root=merkle.root(ids), checkpoint=cp,
                           checkpoint_hash=mirror_hash or checkpoint.hash(cp), network="testnet",
                           created_at_ms=1, tx="tx1", record=1, status="anchored")
    record = {"seq": 1, "checkpoint": cp, "checkpointHash": to_hex(checkpoint.hash(cp)),
              "tx": "tx1", "record": 1, "network": "testnet"}
    return respx_mock.get(f"{ANCHOR}/checkpoints/1").mock(
        return_value=httpx.Response(200, json=record)), cp


async def test_r11_anchor_matches(engine, store, respx_mock):
    route, _ = await _anchor_fixture(store, respx_mock)
    assert await engine.periodic((T0 + 5) * 1000) == []
    assert await engine.periodic((T0 + 6) * 1000) == []
    assert route.call_count == 1  # an on-chain record never changes
    assert (await store.stats())["anchor"] == "ok"


async def test_r11_anchor_mismatch(engine, store, respx_mock):
    _, cp = await _anchor_fixture(store, respx_mock, rewrite=True)
    [a] = await engine.periodic((T0 + 5) * 1000)
    assert (a.rule, a.severity) == ("ANCHOR_MISMATCH", "critical")
    assert a.evidence["onchainMsRoot"] == cp["msRoot"]
    assert a.evidence["recomputedMsRoot"] != cp["msRoot"]
    assert a.evidence["window"] == {"from": 10, "to": 13}
    assert (await store.anchors())[0]["status"] == "mismatch"
    assert await engine.periodic((T0 + 6) * 1000) == []


async def test_r11_mirror_differs_from_chain(engine, store, respx_mock):
    await _anchor_fixture(store, respx_mock, mirror_hash=blake2b256(b"forged mirror"))
    [a] = await engine.periodic((T0 + 5) * 1000)
    assert a.rule == "ANCHOR_MISMATCH" and "mirror" in a.evidence["reason"]


async def test_r11_anchor_unreachable(engine, store, respx_mock):
    route, _ = await _anchor_fixture(store, respx_mock, rewrite=True)
    route.mock(side_effect=httpx.ConnectError("refused"))
    assert await engine.periodic((T0 + 5) * 1000) == []
    assert (await store.stats())["anchor"] == "unreachable"


async def test_r14_shadow_grace_and_exempt_tags(make_engine, store):
    engine = make_engine(shadow_exempt_tags=frozenset({"LLO-K8s"}))
    so = {"infrastructureElementId": URN + IE, "errorCode": "E1"}
    via_api = message("self-orchestrator", so, verdict=V.UNSIGNED_LEGACY, **at(0))
    await store.put_submission(Submission(sub_id="s1", source="mqtt",
                                          received_at_ms=T0 * 1000 - 5000,
                                          block_id=via_api.block_id))
    bypass = message("self-orchestrator", {**so, "errorCode": "E2"}, verdict=V.UNSIGNED_LEGACY,
                     **at(1))
    exempt = message("LLO-K8s", {"event": "e", "lloId": "l", "serviceComponentId": "s"},
                     verdict=V.UNSIGNED_LEGACY, **at(1))
    for row in (via_api, bypass, exempt):
        assert await ingest(engine, row) == []
    confirmed = (T0 + 60) * 1000
    assert await engine.periodic(confirmed + 10_000) == []
    [a] = await engine.periodic(confirmed + 31_000)
    assert (a.rule, a.severity, a.block_id) == ("SHADOW", "high", bypass.block_id)
    assert (await store.lifecycle(bypass.block_id))[-1]["status"] == "SHADOW"
    assert await engine.periodic(confirmed + 40_000) == []


async def test_r14_shadow_needs_a_baseline(engine, store):
    row = message("self-orchestrator", {"infrastructureElementId": URN + IE, "errorCode": "E1"},
                  verdict=V.UNSIGNED_LEGACY, **at(0))
    assert await ingest(engine, row) == []
    assert await engine.periodic((T0 + 100) * 1000) == []  # no submission ever: no baseline


async def test_missing_in_db_from_rescan(engine, store):
    row = Writer().score(0.8, **at(0))
    assert await ingest(engine, row) == []
    wiped = blake2b256(b"wiped from the parallel database")
    [a] = await engine.rescan([row.block_id, wiped])
    assert (a.rule, a.severity, a.block_id) == ("MISSING_IN_DB", "critical", wiped)
    assert await engine.rescan([row.block_id, wiped]) == []


# ---------------------------------------------------------------- whole traffic


async def test_genuine_traffic_no_alerts(engine, orion, store):
    rng = random.Random(7)
    w = Writer()
    score = 0.8
    for m in range(50):
        score = min(1.0, max(0.0, round(score + rng.uniform(-0.05, 0.05), 3)))
        row = w.score(score, **at(m))
        await store.put_submission(Submission(sub_id=f"s{m}", source="mqtt",
                                              received_at_ms=at(m)["ts"] * 1000 - 3000,
                                              block_id=row.block_id))
        assert await ingest(engine, row) == [], m
    orion.scores[IE] = score
    last = at(49)["ts"] * 1000
    assert await engine.periodic(last + 31_000) == []
    assert await engine.periodic(last + 100_000) == []
    assert (await store.stats())["alerts"] == 0


def test_severities_are_fixed():
    assert SEVERITY == {
        "FORGED": "critical", "ANCHOR_MISMATCH": "critical", "MISSING_IN_DB": "critical",
        "REPLAY": "high", "UNAUTHORIZED_WRITER": "high", "REVOKED_KEY": "high",
        "CHAIN_FORK": "high", "SHADOW": "high",
        "DRIFT": "medium", "ANOMALY": "medium", "CHAIN_GAP": "medium", "UNSIGNED": "medium",
        "STALE": "low", "UNKNOWN_IE": "low", "CLOCK_SKEW": "low", "MALFORMED": "low",
    }
