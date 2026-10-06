import inspect
import json
import re
from pathlib import Path

from helpers import VALIDATOR_ALERTS
from witness_chaos import attacks
from witness_core import verdicts
from witness_core.bundle import STEP_NAMES
from witness_indexer import rules, validator

KEY = Path(attacks.__file__).with_name("answer_key.yaml")
POLICY = Path(__file__).resolve().parents[1] / "demo-policy.json"
IDENTITIES = Path(__file__).resolve().parents[2] / "deploy" / "identity" / "testnet.json"

VERDICTS = {v for k, v in vars(verdicts).items() if k.isupper() and isinstance(v, str)}
PRIMARY = {"verdict", "alert", "ladder", "ladder_overall"}
EXTRA = {"severity", "block_verdict", "sealed", "blind_search"}
CHANNELS = {"relay", "hornet-direct", "orion", "db", "bundle-offline"}


def test_answer_key_complete(key):
    classes = key["classes"]
    ids = [c["id"] for c in classes]
    assert ids == [f"A{i:02d}" for i in range(1, 21)]
    assert len({c["name"] for c in classes}) == 20
    for c in classes:
        assert c["description"].strip() and c["name"]
        assert c["trials"] == 20 and c["timeout_s"] > 0
        assert c["channel"] in CHANNELS
        assert len(PRIMARY & set(c["expect"])) == 1, c["id"]
        assert set(c["expect"]) <= PRIMARY | EXTRA, c["id"]
        assert isinstance(c["allowed_side_alerts"], list), c["id"]
        fn = getattr(attacks, c["inject"], None)
        assert inspect.iscoroutinefunction(fn), c["id"]
        assert list(inspect.signature(fn).parameters) == ["ctx"]
    assert len({c["inject"] for c in classes}) == 20


def test_expected_strings_exist_in_code(key):
    for c in key["classes"]:
        e = c["expect"]
        if "verdict" in e:
            assert e["verdict"] in VERDICTS, c["id"]
        elif "alert" in e:
            rule = e["alert"]
            sev = rules.SEVERITY.get(rule) or VALIDATOR_ALERTS.get(rule)
            assert sev, f"{c['id']}: no code emits alert {rule}"
            assert e.get("severity", sev) == sev, c["id"]
        elif "ladder" in e:
            assert e["ladder"]["step"] in STEP_NAMES and e["ladder"]["ok"] is False
        else:
            assert e["ladder_overall"] == "INVALID"


def test_validator_alert_names_are_in_validator_source():
    src = inspect.getsource(validator)
    for name, sev in VALIDATOR_ALERTS.items():
        assert re.search(rf'Alert\(\s*"{name}",\s*"{sev}"', src), name


def test_channels_match_attack_kind(key):
    offline = {c["id"] for c in key["classes"] if c["channel"] == "bundle-offline"}
    assert offline == {"A07", "A08", "A09", "A10"}
    for c in key["classes"]:
        assert ("ladder" in c["expect"]) == (c["channel"] == "bundle-offline")


def test_traps_defined(key):
    t = key["traps"]
    assert t["duration_min"] >= 30 and t["min_messages"] >= 500
    assert t["expect"]["alerts"] == 0
    assert set(t["expect"]["verdicts"]) <= VERDICTS
    assert {p["verdict"] for p in t["profile"]} <= set(t["expect"]["verdicts"])
    assert {p["tag"] for p in t["profile"]} == {
        "trust.score", "LLO-K8s", "LLO-Docker", "self-orchestrator"}


def test_demo_policy_matches_identities(key):
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    dids = {i["name"]: i["did"] for i in json.loads(IDENTITIES.read_text())["identities"]}
    ts = policy["tags"]["trust.score"]
    assert ts["allowed"] == [dids["trust-manager"]]
    assert ts["require_signature"] is True and ts["legacy_grace"] is False
    for tag in ("LLO-K8s", "LLO-Docker", "self-orchestrator", "self-security"):
        rule = policy["tags"][tag]
        assert dids["relay"] in rule["allowed"] and rule["legacy_grace"] is True
        assert rule["require_signature"] is False
    # self-security has no identity of its own: only the relay may attest its notifications
    assert policy["tags"]["self-security"]["allowed"] == [dids["relay"]]
    from witness_core import policy as policy_mod

    loaded = policy_mod.load(policy)
    assert policy_mod.allowed(loaded, "trust.score", dids["trust-manager"])
    assert not policy_mod.allowed(loaded, "trust.score", dids["relay"])
    assert key["policy"] == "demo-policy.json"
