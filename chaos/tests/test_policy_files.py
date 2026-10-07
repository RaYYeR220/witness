"""The deployment's writer policy is the evaluation's, and follows from the identity file."""

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _make_policy_module():
    spec = importlib.util.spec_from_file_location("make_policy", ROOT / "scripts" / "make_policy.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_deploy_policy_is_the_evaluation_policy():
    assert _load(ROOT / "deploy" / "policy.json") == _load(ROOT / "chaos" / "demo-policy.json")


def test_deploy_policy_follows_from_the_identity_file():
    make_policy = _make_policy_module().make_policy
    identity = _load(ROOT / "deploy" / "identity" / "testnet.json")
    assert make_policy(identity) == _load(ROOT / "deploy" / "policy.json")


def test_make_policy_names_missing_components():
    make_policy = _make_policy_module().make_policy
    try:
        make_policy({"identities": [{"name": "relay", "did": "did:example:relay"}]})
    except ValueError as e:
        assert "anchor" in str(e) and "trust-manager" in str(e)
    else:
        raise AssertionError("a missing component must be refused")
