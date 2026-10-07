"""Tests for the pre-run amendments: side alerts, A11 assertions, A17, A07, per-trial IEs."""

import random

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from helpers import VALIDATOR_ALERTS, cls, make
from witness_chaos import attacks as A
from witness_chaos import forge, scorecard
from witness_core import sealed as S
from witness_indexer import rules


@pytest.fixture
def ctx(real_bundle, cfg, sample_keys):
    return A.AttackContext(rng=random.Random(3), real_bundle=real_bundle, verifier=cfg,
                           sample_private_keys=sample_keys)


# ---------------------------------------------------------------- answer key


def test_side_alerts_are_real_rules_and_pre_registered(key):
    known = set(rules.SEVERITY) | set(VALIDATOR_ALERTS)
    for c in key["classes"]:
        side = c["allowed_side_alerts"]
        assert set(side) <= known, c["id"]
        assert c["expect"].get("alert") not in side, c["id"]
        if c["channel"] == "hornet-direct" and c["id"] != "A17":
            assert "SHADOW" in side, c["id"]
    assert key["amendments"][0]["before_first_run"] is True


def test_a11_a17_a07_assertions_and_control(key):
    by = {c["id"]: c for c in key["classes"]}
    assert by["A11"]["expect"]["sealed"] is True
    assert by["A11"]["expect"]["blind_search"] is True
    assert by["A17"]["expect"]["block_verdict"] == "PRODUCER_SIGNED"
    assert by["A07"]["expect"]["ladder"]["parses"] is True
    ctl = key["controls"][0]
    assert ctl["expect"]["no_alert"] == "SHADOW"
    assert ctl["channel"] == "relay"
    for cid in ("A06", "A13", "A14", "A17"):
        assert by[cid]["per_trial_ie"] is True


# ---------------------------------------------------------------- attacks


@pytest.mark.parametrize("seed", range(10))
async def test_a07_flips_only_inside_the_payload_and_still_parses(ctx, seed, no_network):
    ctx.rng = random.Random(seed)
    rec = await A.a07_block_byte_flip(ctx)
    assert rec.detail["parses"] is True
    assert rec.detail["steps"]["block_hash"] is False
    real = bytes.fromhex(ctx.real_bundle["block"]["raw"][2:])
    flipped = bytes.fromhex(rec.detail["bundle"]["block"]["raw"][2:])
    diff = [i for i, (a, b) in enumerate(zip(real, flipped, strict=True)) if a != b]
    assert len(diff) == 1
    lo, hi = forge._data_region(real)
    assert lo <= diff[0] < hi


def test_meets_offline_expectation_rejects_wrong_reason():
    expect = {"ladder": {"step": "block_hash", "ok": False, "parses": True}}
    assert A.meets_offline_expectation(expect, {"steps": {"block_hash": False}, "parses": True})
    assert not A.meets_offline_expectation(
        expect, {"steps": {"block_hash": False}, "parses": False})
    assert not A.meets_offline_expectation(expect, {"steps": {"block_hash": None}, "parses": True})


def test_begin_trial_gives_fresh_ids_and_baselines(ctx):
    seen = set()
    for _ in range(5):
        ctx.begin_trial()
        seen.add((ctx.ie_id, ctx.stale_ie_id, ctx.baseline_score))
        assert ctx.ie_id != ctx.stale_ie_id
        assert 0.4 <= ctx.baseline_score <= 0.6
    assert len(seen) == 5
    ctx.ie_pool = ["D:000000000001"]
    ctx.begin_trial()
    assert ctx.ie_id == "D:000000000001"


def _sealed_message(ctx):
    plain = A.build_a11(ctx)
    kid = "did:iota:testnet:0xdd#kex-1"
    recipient = X25519PrivateKey.generate()
    enc = S.encrypt_body(plain, [S.Recipient(kid, recipient.public_key().public_bytes_raw())])
    return plain, {"w": 1, "tag": A.SEALED_TAG, "enc": enc}


def test_a11_sealed_check_passes_for_a_sealed_message(ctx):
    plain, stored = _sealed_message(ctx)
    ok, why = A.check_sealed(stored, plain)
    assert ok, why


def test_a11_sealed_check_fails_on_plaintext_or_missing_enc(ctx):
    plain, stored = _sealed_message(ctx)
    assert not A.check_sealed({**stored, "body": plain}, plain)[0]
    assert not A.check_sealed({"w": 1, "body": plain}, plain)[0]
    assert not A.check_sealed({**stored, "note": plain["secret"]}, plain)[0]
    assert not A.check_sealed("nope", plain)[0]


def test_a11_sealed_check_scans_everything_the_explorer_serves(ctx):
    plain, stored = _sealed_message(ctx)
    clean = {"verdict": "RELAY_ATTESTED", "content": None,
             "submission": {"message": None, "dataHex": "0x00"}}
    assert A.check_sealed(stored, plain, served=clean)[0]
    leaked = {**clean, "submission": {"message": plain, "dataHex": "0x00"}}
    ok, why = A.check_sealed(stored, plain, served=leaked)
    assert not ok and "explorer's answer" in why
    assert not A.check_sealed(stored, plain, served={**clean, "content": plain})[0]


def test_a11_blind_search(ctx):
    ctx.search_key = b"k" * 32
    tok = A.blind_token_for(ctx)
    assert tok == A.blind_token_for(ctx)
    ctx.search_key = b"x" * 32
    assert A.blind_token_for(ctx) != tok
    assert A.check_blind_search(["0xAB", "0xcd"], "0xab")
    assert not A.check_blind_search(["0xcd"], "0xab")
    assert not A.check_blind_search(["0xab"], None)


# ---------------------------------------------------------------- scorecard


def test_side_alerts_are_ignored_and_reported_unexpected_ones_counted(key):
    side, bad = scorecard.alert_buckets(cls(key, "A01"), ["FORGED", "SHADOW", "CLOCK_SKEW"])
    assert side == ["FORGED", "SHADOW"]
    assert bad == ["CLOCK_SKEW"]
    assert scorecard.alert_buckets(cls(key, "A06"), ["DRIFT", "DRIFT"]) == ([], [])


def test_side_alerts_do_not_break_detection_but_show_in_scorecard(key):
    res = make(key)
    for r in res:
        if r["class"] == "A01":
            r["alerts"] = ["FORGED", "SHADOW"]
        if r["class"] == "A06" and r["trial"] < 2:
            r["alerts"] = ["DRIFT", "ANOMALY"]
    card = scorecard.build_scorecard(res, None, key)
    a01 = card["classes"][0]
    assert a01["detected"] == 20
    assert a01["side_alerts"] == {"FORGED": 20, "SHADOW": 20}
    assert a01["unexpected_alerts"] == {}
    a06 = next(r for r in card["classes"] if r["id"] == "A06")
    assert a06["unexpected_alerts"] == {"ANOMALY": 2}
    assert card["unexpected_alerts"] == 2
    md = scorecard.render_markdown(card)
    assert "A01: side FORGED x20, SHADOW x20; unexpected -" in md
    assert "A06: side -; unexpected ANOMALY x2" in md


def test_a11_detected_only_when_every_assertion_holds(key):
    c = cls(key, "A11")
    good = {"verdict": "RELAY_ATTESTED", "alerts": [], "sealed": True, "blind_search": True}
    assert scorecard.evaluate_trial(c, good)["detected"] is True
    for broken in ({"sealed": False}, {"blind_search": False}, {"sealed": None},
                   {"verdict": "FORGED"}):
        assert scorecard.evaluate_trial(c, {**good, **broken})["detected"] is False


def test_a17_needs_shadow_and_producer_signed_verdict(key):
    c = cls(key, "A17")
    ok = {"verdict": "PRODUCER_SIGNED", "alerts": ["SHADOW"]}
    assert scorecard.evaluate_trial(c, ok)["detected"] is True
    assert scorecard.evaluate_trial(c, {**ok, "verdict": "FORGED"})["detected"] is False
    assert scorecard.evaluate_trial(c, {**ok, "alerts": []})["detected"] is False


def test_a07_needs_hash_red_and_block_still_parses(key):
    c = cls(key, "A07")
    ok = {"ladder": {"block_hash": False}, "parses": True}
    assert scorecard.evaluate_trial(c, ok)["detected"] is True
    assert scorecard.evaluate_trial(c, {**ok, "parses": False})["detected"] is False
    assert scorecard.evaluate_trial(c, {**ok, "ladder": {"block_hash": None}})["detected"] is False


def test_evaluate_verdict_and_alert_classes_and_miss_label(key):
    forged = scorecard.evaluate_trial(cls(key, "A01"), {"verdict": "FORGED", "alerts": []})
    assert forged["detected"]
    assert forged["observed"] == "FORGED"
    miss = scorecard.evaluate_trial(cls(key, "A06"), {"verdict": None, "alerts": ["STALE"]})
    assert miss == {"detected": False, "observed": "STALE", "alerts": ["STALE"]}
    assert scorecard.evaluate_trial(cls(key, "A06"), {})["observed"] is None


def test_control_and_scorecard_control_section(key):
    ctl = key["controls"][0]
    assert scorecard.control_passed(ctl, [])
    assert not scorecard.control_passed(ctl, ["SHADOW"])
    assert not scorecard.control_passed(ctl, ["CLOCK_SKEW"])
    ok = {"control": "C01", "trial": 0, "status": "ok", "blockId": "0x01", "indexed": True,
          "verdict": "PRODUCER_SIGNED", "alerts": []}
    card = scorecard.build_scorecard(
        make(key), None, key, [ok, {**ok, "trial": 1, "alerts": ["SHADOW"]}])
    assert (card["controls"]["trials"], card["controls"]["passed"]) == (2, 1)
    assert card["valid"] is False
    assert "Positive control: 1/2" in scorecard.render_markdown(card)


def test_producer_amendment_keeps_every_expectation(key):
    second = key["amendments"][1]
    assert str(second["date"]) == "2026-10-07" and second["before_first_run"] is True
    assert any("chaos-only did:key" in c for c in second["changes"])
    # The amendment changes who signs, not what is expected.
    assert {c["id"]: c["expect"] for c in key["classes"]}["A17"] == {
        "alert": "SHADOW", "severity": "high", "block_verdict": "PRODUCER_SIGNED"}
