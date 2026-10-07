import copy
import json
import random

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_chaos import attacks as A
from witness_chaos import forge
from witness_core import envelope, schema, verdicts
from witness_core.bundle import STEP_NAMES
from witness_core.envelope import KeyInfo
from witness_indexer.ingest import parse_record
from witness_indexer.rules import RulesConfig

PRODUCER = A.Identity("did:iota:testnet:0xaa", "did:iota:testnet:0xaa#sig-1",
                      Ed25519PrivateKey.generate())
OUTSIDER = A.Identity("did:iota:testnet:0xbb", "did:iota:testnet:0xbb#sig-1",
                      Ed25519PrivateKey.generate())
REVOKED = A.Identity("did:iota:testnet:0xcc", "did:iota:testnet:0xcc#sig-1",
                     Ed25519PrivateKey.generate())


def resolver(*idents):
    table = {i.kid: KeyInfo(i.kid, i.key.public_key().public_bytes_raw(), None, None)
             for i in idents}
    return table.get


@pytest.fixture
def ctx(real_bundle, cfg, sample_keys):
    return A.AttackContext(
        producer=PRODUCER, outsider=OUTSIDER, revoked=REVOKED, rng=random.Random(7),
        real_bundle=real_bundle, sample_private_keys=sample_keys, verifier=cfg,
        clock_ms=lambda: 1_800_000_000_000)


def check(data, tag, *idents):
    return envelope.verify(json.loads(data), tag, resolver(*idents))


def test_a01_signature_is_from_the_attacker(ctx):
    tag, data = A.build_a01(ctx)
    c = check(data, tag, PRODUCER)
    assert (c.verdict, c.iss) == (verdicts.FORGED, PRODUCER.iss)
    assert "signature invalid" in c.reason
    # With the attacker's key published the signature would verify: it is theirs.
    atk = A.Identity(PRODUCER.iss, PRODUCER.kid, ctx.attacker_key)
    assert check(data, tag, atk).verdict == verdicts.PRODUCER_SIGNED


def test_a02_valid_envelope_under_another_tag(ctx):
    tag, data = A.build_a02(ctx)
    assert tag != A.TRUST_TAG
    assert json.loads(data)["tag"] == A.TRUST_TAG
    assert check(data, A.TRUST_TAG, PRODUCER).verdict == verdicts.PRODUCER_SIGNED
    c = check(data, tag, PRODUCER)
    assert c.verdict == verdicts.FORGED
    assert "tag" in c.reason


def test_a03_same_iss_seq_fresh_nonce(ctx):
    (t1, d1), (t2, d2) = A.build_a03(ctx)
    e1, e2 = json.loads(d1), json.loads(d2)
    assert t1 == t2 == A.TRUST_TAG
    assert (e1["iss"], e1["seq"]) == (e2["iss"], e2["seq"])
    assert e1["nonce"] != e2["nonce"]
    assert d1 != d2
    assert check(d2, t2, PRODUCER).verdict == verdicts.PRODUCER_SIGNED


def test_a04_a05_signed_by_the_named_identity(ctx):
    for build, ident in ((A.build_a04, OUTSIDER), (A.build_a05, REVOKED)):
        tag, data = build(ctx)
        c = check(data, tag, ident)
        assert c.verdict == verdicts.PRODUCER_SIGNED
        assert c.iss == ident.iss


def test_a12_unknown_ie_is_well_formed(ctx):
    tag, data, ie = A.build_a12(ctx)
    cl = schema.classify(tag, data)
    assert cl.schema_ok
    assert cl.ie_id == ie
    assert ie != ctx.ie_id


def test_a13_jump_exceeds_threshold(ctx):
    (_, d1), (_, d2) = A.build_a13(ctx)
    s = [json.loads(d)["body"]["score"] for d in (d1, d2)]
    assert abs(s[1] - s[0]) > RulesConfig().jump_threshold
    assert json.loads(d1)["seq"] < json.loads(d2)["seq"]


def test_a15_signed_but_schema_breaking(ctx):
    tag, data = A.build_a15(ctx)
    assert check(data, tag, PRODUCER).verdict == verdicts.PRODUCER_SIGNED
    assert schema.classify(tag, data).schema_ok is False


def test_a20_prev_names_a_block_never_sent(ctx):
    m1, m3, missing = A.build_a20(ctx)
    assert m3["prev"] == missing
    assert "prev" not in m1
    assert m3["seq"] == m1["seq"] + 2
    assert envelope.verify(m3, A.TRUST_TAG, resolver(PRODUCER)).verdict \
        == verdicts.PRODUCER_SIGNED


def test_hornet_request_shape():
    path, body = A.hornet_request("trust.score", b"hi")
    assert path == "/api/core/v2/blocks"
    assert body == {"protocolVersion": 2,
                    "payload": {"type": 5, "tag": "0x" + b"trust.score".hex(),
                                "data": "0x6869"}}


def test_relay_upload_request(ctx):
    ctx.relay_token = "tok"
    url, body, headers = A.relay_upload(ctx, "audit.report", {"a": 1})
    assert url.endswith("/upload?node=default")
    assert body == {"tag": "audit.report", "message": {"a": 1}}
    assert headers["Authorization"] == "Bearer tok"


def test_a16_record_differs_from_sent_bytes(ctx):
    _, data = A.build_a17(ctx)
    rec = A.build_a16_record("0x" + "11" * 32, A.TRUST_TAG, data, 5)
    sent = bytes.fromhex(rec["dataHex"][2:])
    assert sent != data
    assert len(sent) == len(data)
    assert sum(a != b for a, b in zip(sent, data, strict=True)) == 1
    assert parse_record(rec, source="http").block_id == bytes.fromhex("11" * 32)


def test_a18_record_names_a_ghost_block(ctx):
    rec = A.build_a18_record(ctx)
    sub = parse_record(rec, source="http")
    assert sub.block_id is not None
    assert sub.data_hex == rec["dataHex"]
    assert A.build_a18_record(ctx)["blockId"] != rec["blockId"]


def test_orion_patch_moves_far_from_ledger(ctx):
    url, body = A.orion_patch(ctx, "Dom:aabbccddeeff", 0.8)
    assert url.endswith("/ngsi-ld/v1/entities/urn:ngsi-ld:InfrastructureElement:"
                        "Dom:aabbccddeeff/attrs/trustScore")
    assert abs(body["value"] - 0.8) > 0.5
    assert abs(A.orion_patch(ctx, "x:y", 0.2)[1]["value"] - 0.2) > 0.5


def test_db_sql_is_parameterised():
    assert A.VICTIM_SQL.count("%s") == 3
    assert "iss = %s" in A.VICTIM_SQL  # only rows the run's own producer signed
    assert A.TAMPER_SQL.count("%s") == 1
    assert A.TAMPER_SQL.startswith("UPDATE messages SET data =")


def test_seq_strictly_increases(ctx):
    seqs = [ctx.next_seq("did:x") for _ in range(3)]
    assert seqs == sorted(set(seqs))


LIVE = ["a01_forged_signature", "a02_cross_tag_replay", "a03_seq_replay",
        "a04_unauthorized_writer", "a05_revoked_key", "a06_orion_drift",
        "a11_sealed_without_key", "a12_unknown_ie", "a13_score_jump", "a14_stale_ie",
        "a15_malformed_payload", "a16_content_mismatch", "a17_shadow", "a18_orphaned",
        "a19_db_tamper", "a20_chain_gap"]


@pytest.mark.parametrize("name", LIVE)
async def test_live_attacks_refuse_without_live_flag(ctx, name, no_network):
    assert ctx.live is False
    with pytest.raises(A.LiveDisabled):
        await getattr(A, name)(ctx)


def test_every_class_has_an_attack():
    ids = {c["inject"] for c in A.answer_key()["classes"]}
    assert ids == set(LIVE) | {"a07_block_byte_flip", "a08_bad_merkle_path",
                               "a09_sample_key_forged_milestone", "a10_anchor_mismatch"}


@pytest.mark.parametrize(("name", "cid", "step"), [
    ("a07_block_byte_flip", "A07", "block_hash"),
    ("a08_bad_merkle_path", "A08", "inclusion"),
    ("a09_sample_key_forged_milestone", "A09", "anchor"),
    ("a10_anchor_mismatch", "A10", "anchor"),
])
async def test_offline_attacks_meet_their_expectation(ctx, name, cid, step, no_network):
    rec = await getattr(A, name)(ctx)
    assert isinstance(rec, A.InjectionRecord)
    assert rec.id == cid
    want = {"step": step, "ok": False}
    if cid == "A07":
        want["parses"] = True
    assert rec.expected == {"ladder": want}
    assert rec.detail["steps"][step] is False
    assert A.meets_offline_expectation(rec.expected, rec.detail)
    assert step in STEP_NAMES
    assert rec.block_id == rec.detail["bundle"]["block"]["id"]


async def test_a09_keeps_steps_one_to_three_green(ctx, no_network):
    rec = await A.a09_sample_key_forged_milestone(ctx)
    s = rec.detail["steps"]
    assert (s["block_hash"], s["inclusion"], s["milestone_signatures"]) == (True,) * 3


async def test_offline_attacks_leave_real_bundle_alone(ctx, no_network):
    before = copy.deepcopy(ctx.real_bundle)
    for fn in (A.a07_block_byte_flip, A.a08_bad_merkle_path,
               A.a09_sample_key_forged_milestone, A.a10_anchor_mismatch):
        await fn(ctx)
    assert ctx.real_bundle == before
    assert forge.real_anchor_record(before)["checkpoint"] == before["anchor"]["checkpoint"]
