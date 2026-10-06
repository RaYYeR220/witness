import json

import pytest
import yaml
from helpers import make
from witness_chaos import scorecard


def test_percentile_nearest_rank():
    assert scorecard.percentile([], 50) is None
    assert scorecard.percentile([5], 95) == 5
    vals = list(range(1, 21))
    assert scorecard.percentile(vals, 50) == 10
    assert scorecard.percentile(vals, 95) == 19


def test_perfect_run(key):
    card = scorecard.build_scorecard(make(key), None, key)
    assert (card["detected"], card["attacks"]) == (400, 400)
    assert card["detection_rate"] == 1.0
    assert card["headline"] == "detected 400/400 attacks"
    assert card["classes"][0]["latency_p50_ms"] == 10_000
    assert card["classes"][0]["latency_p95_ms"] == 19_000


def test_confusion_matrix_counts_misses_and_wrong_outcomes(key):
    res = make(key, misses={"A01": 3}, wrong={"A01": 2, "A02": 1})
    m = scorecard.confusion_matrix(res, key["classes"])
    assert m["A01"] == {"NONE": 3, "PRODUCER_SIGNED": 2, "FORGED": 15}
    assert m["A02"]["PRODUCER_SIGNED"] == 1
    card = scorecard.build_scorecard(res, None, key)
    a01 = card["classes"][0]
    assert a01["detected"] == 15
    assert a01["rate"] == 0.75
    assert card["detected"] == 400 - 6


def test_unknown_class_rejected(key):
    with pytest.raises(KeyError):
        scorecard.confusion_matrix([{"class": "A99", "observed": "x"}], key["classes"])


def test_labels_cover_every_expect_form():
    assert scorecard.expected_label({"verdict": "FORGED"}) == "FORGED"
    assert scorecard.expected_label({"alert": "DRIFT", "severity": "medium"}) == "DRIFT"
    assert scorecard.expected_label({"ladder": {"step": "anchor", "ok": False}}) \
        == "ladder:anchor"
    assert scorecard.expected_label({"ladder_overall": "INVALID"}) == "ladder_overall:INVALID"


def test_trap_false_positives(key):
    ok = {"messages": 520, "duration_s": 1900, "alerts": 0,
          "verdicts": {"PRODUCER_SIGNED": 300, "RELAY_ATTESTED": 150, "UNSIGNED_LEGACY": 70}}
    card = scorecard.build_scorecard(make(key), ok, key)
    assert card["traps"]["false_positives"] == 0
    assert card["traps"]["meets_profile"]
    assert card["headline"] == "detected 400/400 attacks, 0/520 false positives"
    bad = {**ok, "alerts": 2, "verdicts": {**ok["verdicts"], "FORGED": 1}}
    assert scorecard.trap_false_positives(bad, key["traps"]["expect"]["verdicts"]) == 3


def test_short_trap_run_is_flagged(key):
    short = {"messages": 100, "duration_s": 60, "alerts": 0, "verdicts": {}}
    card = scorecard.build_scorecard(make(key), short, key)
    assert card["traps"]["meets_profile"] is False
    assert "below the pre-registered profile" in scorecard.render_markdown(card)


def test_scorecard_is_json_serialisable_and_markdown_renders(key):
    trap = {"messages": 600, "duration_s": 2000, "alerts": 0,
            "verdicts": {"PRODUCER_SIGNED": 600}}
    card = scorecard.build_scorecard(make(key, misses={"A06": 2}), trap, key)
    assert json.loads(json.dumps(card))["schema"] == scorecard.SCHEMA
    md = scorecard.render_markdown(card)
    assert md.startswith("**detected 398/400 attacks, 0/600 false positives**")
    assert "| A06 | ORION_DRIFT | DRIFT | 18/20 | 90% |" in md
    assert "NONE x2" in md
    assert len([ln for ln in md.splitlines() if ln.startswith("| A")]) == 20


def test_key_roundtrips_through_yaml(key):
    assert yaml.safe_load(yaml.safe_dump(key)) == key
