"""The witness CLI: exit codes of the offline verifier and the query commands."""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner
from witness_cli.main import app

VECTORS = Path(__file__).resolve().parents[2] / "core" / "tests" / "vectors" / "bundles.json"
API = "http://api.test"
ANCHOR = "http://anchor.test"
RESOLVER = "http://resolver.test"

runner = CliRunner()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("WITNESS_API_URL", "WITNESS_ANCHOR_URL", "WITNESS_RESOLVER_URL",
                 "WITNESS_VERIFIER_CONFIG", "WITNESS_REPORT_TOKEN", "WITNESS_POSTURE_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLUMNS", "220")


@pytest.fixture(scope="module")
def vectors() -> dict:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def case(vectors: dict, name: str) -> dict:
    return next(c for c in vectors["cases"] if c["name"] == name)


@pytest.fixture
def files(tmp_path, vectors):
    def make(name: str) -> dict[str, Path]:
        c = case(vectors, name)
        bundle = tmp_path / f"{name}.bundle.json"
        bundle.write_text(json.dumps(c["bundle"]), encoding="utf-8")
        config = tmp_path / f"{name}.config.json"
        config.write_text(json.dumps(c["config"]), encoding="utf-8")
        out = {"bundle": bundle, "config": config}
        if c["resolver"]:
            snap = tmp_path / f"{name}.did.json"
            registry = vectors["resolvers"][c["resolver"]]
            snap.write_text(json.dumps(next(iter(registry.values()))), encoding="utf-8")
            out["snapshot"] = snap
        return out
    return make


def anchor_reply(vectors: dict, name: str = "valid_anchored") -> dict:
    c = case(vectors, name)
    a = c["bundle"]["anchor"]
    return {"seq": a["rebased"]["record"], "checkpoint": a["checkpoint"],
            "checkpointHash": c["fetcher"]["record"]["checkpointHash"], "tx": "x",
            "record": a["rebased"]["record"], "network": a["rebased"]["network"],
            "trail": a["rebased"]["trail"], "source": "chain", "readAtMs": 1}


# ---------------------------------------------------------------- verify

def test_verify_valid_without_anchor_is_partial(files):
    f = files("valid_anchored")
    r = runner.invoke(app, ["verify", str(f["bundle"]), "--config", str(f["config"]),
                            "--did-snapshot", str(f["snapshot"])])
    assert r.exit_code == 2, r.output
    assert "PARTIAL" in r.output


def test_verify_nothing_trusted_is_partial_never_valid(files):
    f = files("valid_anchored")
    r = runner.invoke(app, ["verify", str(f["bundle"]), "--config", str(f["config"])])
    assert r.exit_code == 2
    assert "PARTIAL" in r.output


@pytest.mark.parametrize("name", ["raw_byte_flipped", "signature_corrupted", "path_hash_corrupted",
                                  "untrusted_key_set"])
def test_verify_negative_is_invalid(files, name):
    f = files(name)
    r = runner.invoke(app, ["verify", str(f["bundle"]), "--config", str(f["config"]),
                            "--did-snapshot", str(f["snapshot"])])
    assert r.exit_code == 1, r.output
    assert "INVALID" in r.output


@respx.mock
def test_verify_valid_with_mocked_anchor_and_resolver_service(files, vectors):
    f = files("valid_anchored")
    respx.get(f"{ANCHOR}/checkpoints/3").mock(
        return_value=httpx.Response(200, json=anchor_reply(vectors)))
    did = next(iter(vectors["resolvers"]["registry"]))
    respx.get(url__regex=rf"{RESOLVER}/resolve/.*").mock(
        return_value=httpx.Response(200, json=vectors["resolvers"]["registry"][did]))
    r = runner.invoke(app, ["verify", str(f["bundle"]), "--config", str(f["config"]),
                            "--anchor-url", ANCHOR, "--resolver", RESOLVER])
    assert r.exit_code == 0, r.output
    assert "VALID" in r.output and "PARTIAL" not in r.output


@respx.mock
def test_verify_anchor_url_from_env_and_no_anchor_flag(files, vectors, monkeypatch):
    f = files("valid_anchored")
    route = respx.get(f"{ANCHOR}/checkpoints/3").mock(
        return_value=httpx.Response(200, json=anchor_reply(vectors)))
    monkeypatch.setenv("WITNESS_ANCHOR_URL", ANCHOR)
    args = ["verify", str(f["bundle"]), "--config", str(f["config"]),
            "--did-snapshot", str(f["snapshot"])]
    assert runner.invoke(app, args).exit_code == 0
    assert route.call_count == 1
    assert runner.invoke(app, [*args, "--no-anchor"]).exit_code == 2
    assert route.call_count == 1


@respx.mock
def test_verify_anchor_on_other_trail_is_not_trusted(files, vectors):
    f = files("valid_anchored")
    reply = anchor_reply(vectors) | {"trail": "0x" + "11" * 33}
    respx.get(f"{ANCHOR}/checkpoints/3").mock(return_value=httpx.Response(200, json=reply))
    r = runner.invoke(app, ["verify", str(f["bundle"]), "--config", str(f["config"]),
                            "--did-snapshot", str(f["snapshot"]), "--anchor-url", ANCHOR])
    assert r.exit_code == 2, r.output


@respx.mock
def test_verify_anchor_service_down_is_partial(files):
    f = files("valid_anchored")
    respx.get(f"{ANCHOR}/checkpoints/3").mock(return_value=httpx.Response(502, json={"error": "x"}))
    r = runner.invoke(app, ["verify", str(f["bundle"]), "--config", str(f["config"]),
                            "--did-snapshot", str(f["snapshot"]), "--anchor-url", ANCHOR])
    assert r.exit_code == 2


def test_verify_without_config_exits_3(files):
    f = files("valid_anchored")
    r = runner.invoke(app, ["verify", str(f["bundle"])])
    assert r.exit_code == 3
    assert "verifier config" in r.output.lower()
    assert "Traceback" not in r.output


def test_verify_config_from_env(files, monkeypatch):
    f = files("raw_byte_flipped")
    monkeypatch.setenv("WITNESS_VERIFIER_CONFIG", str(f["config"]))
    assert runner.invoke(app, ["verify", str(f["bundle"])]).exit_code == 1


def test_verify_bad_files_are_clean_errors(tmp_path, files):
    f = files("valid_anchored")
    junk = tmp_path / "junk.json"
    junk.write_text("{nope", encoding="utf-8")
    assert runner.invoke(app, ["verify", str(junk), "--config", str(f["config"])]).exit_code == 4
    assert runner.invoke(app, ["verify", str(tmp_path / "missing.json"),
                               "--config", str(f["config"])]).exit_code == 4
    assert runner.invoke(app, ["verify", str(f["bundle"]), "--config", str(junk)]).exit_code == 3


def test_verify_json_is_machine_readable(files):
    f = files("valid_anchored")
    r = runner.invoke(app, ["verify", str(f["bundle"]), "--config", str(f["config"]),
                            "--did-snapshot", str(f["snapshot"]), "--json"])
    assert r.exit_code == 2
    doc = json.loads(r.stdout)
    assert doc["overall"] == "PARTIAL"
    assert [s["name"] for s in doc["steps"]] == [
        "block_hash", "inclusion", "milestone_signatures", "envelope", "anchor"]
    assert [s["ok"] for s in doc["steps"]] == [True, True, True, True, None]
    assert all(isinstance(s["detail"], str) for s in doc["steps"])


@respx.mock
def test_verify_from_api_uses_pinned_config_not_api_config(files, vectors):
    f = files("untrusted_key_set")  # pins attacker coordinator keys -> must be INVALID
    good = case(vectors, "valid_anchored")
    respx.get(f"{API}/proofs/0xabc").mock(return_value=httpx.Response(200, json=good["bundle"]))
    cfg_route = respx.get(f"{API}/config/verifier").mock(
        return_value=httpx.Response(200, json=good["config"]))
    r = runner.invoke(app, ["verify", "0xabc", "--from-api", "--api", API,
                            "--config", str(f["config"]), "--did-snapshot", str(f["snapshot"])])
    assert r.exit_code == 1, r.output
    assert not cfg_route.called


@respx.mock
def test_verify_from_api_not_found(files):
    f = files("valid_anchored")
    respx.get(f"{API}/proofs/0xabc").mock(return_value=httpx.Response(404, json={"detail": "no"}))
    r = runner.invoke(app, ["verify", "0xabc", "--from-api", "--api", API,
                            "--config", str(f["config"])])
    assert r.exit_code == 4


# ---------------------------------------------------------------- queries

MSG = {"blockId": "0x" + "ab" * 32, "tag": "trust.score", "kind": "trust.score",
       "verdict": "PRODUCER_SIGNED", "ieId": "MyDomain:fa163e5e25ef", "iss": "did:iota:x:0x1",
       "date": "2026-10-06T10:00:00Z", "msIndex": 371}


@respx.mock
def test_search_prints_rows_and_sends_filters():
    route = respx.get(f"{API}/messages").mock(
        return_value=httpx.Response(200, json={"items": [MSG], "nextCursor": "c2", "limit": 50}))
    r = runner.invoke(app, ["search", "--api", API, "--tag", "trust.score", "--ie", "MyDomain:fa",
                            "--iss", "did:iota:x:0x1", "--verdict", "PRODUCER_SIGNED",
                            "--since", "2026-10-06"])
    assert r.exit_code == 0, r.output
    assert "trust.score" in r.output and "MyDomain:fa163e5e25ef" in r.output
    assert MSG["blockId"] in r.output
    assert "c2" in r.output
    q = dict(route.calls.last.request.url.params)
    assert q == {"tag": "trust.score", "ie": "MyDomain:fa", "iss": "did:iota:x:0x1",
                 "verdict": "PRODUCER_SIGNED", "date_from": "2026-10-06", "limit": "50"}


@respx.mock
def test_search_json_and_api_env(monkeypatch):
    monkeypatch.setenv("WITNESS_API_URL", API)
    page = {"items": [MSG], "nextCursor": None, "limit": 50}
    respx.get(f"{API}/messages").mock(return_value=httpx.Response(200, json=page))
    r = runner.invoke(app, ["search", "--json"])
    assert r.exit_code == 0
    assert json.loads(r.stdout) == page


@respx.mock
def test_api_error_is_clean_exit_4():
    respx.get(f"{API}/messages").mock(
        return_value=httpx.Response(400, json={"detail": "bad cursor"}))
    r = runner.invoke(app, ["search", "--api", API])
    assert r.exit_code == 4
    assert "bad cursor" in r.output
    assert "Traceback" not in r.output


@respx.mock
def test_api_unreachable_is_clean_exit_4():
    respx.get(f"{API}/messages").mock(side_effect=httpx.ConnectError("refused"))
    r = runner.invoke(app, ["search", "--api", API])
    assert r.exit_code == 4
    assert "Traceback" not in r.output


@respx.mock
def test_lookup_posts_file_body(tmp_path):
    doc = tmp_path / "d.json"
    doc.write_text('{"a": 1}', encoding="utf-8")
    route = respx.post(f"{API}/lookup").mock(return_value=httpx.Response(200, json={
        "canonHash": "0x" + "01" * 32, "bodyCanonHash": None, "matches": [MSG]}))
    r = runner.invoke(app, ["lookup", str(doc), "--api", API])
    assert r.exit_code == 0, r.output
    assert json.loads(route.calls.last.request.content) == {"a": 1}
    assert MSG["blockId"] in r.output


@respx.mock
def test_lineage_prints_entries():
    body = {"ieId": "MyDomain:fa163e5e25ef", "total": 1, "epsilon": 0.05, "drift": False,
            "ledger": {"score": 0.9, "blockId": MSG["blockId"], "verdict": "PRODUCER_SIGNED",
                       "msIndex": 371},
            "orion": {"status": "ok", "value": 0.91},
            "entries": [{"blockId": MSG["blockId"], "seq": 5, "kind": "trust.score",
                         "verdict": "PRODUCER_SIGNED", "msIndex": 371, "at": "2026-10-06",
                         "score": 0.9}]}
    respx.get(f"{API}/ie/MyDomain:fa163e5e25ef/lineage").mock(
        return_value=httpx.Response(200, json=body))
    r = runner.invoke(app, ["lineage", "MyDomain:fa163e5e25ef", "--api", API])
    assert r.exit_code == 0, r.output
    assert "0.9" in r.output and "371" in r.output


POSTURE = {"scannedAtMs": 1, "scannedAt": "t", "active": False, "summary": {"high": 1},
           "findings": [{"id": "sample-coordinator-keys", "severity": "high",
                         "title": "Sample keys", "evidence": {}, "fix": "rotate"}]}


@respx.mock
def test_posture_reads_without_token():
    respx.get(f"{API}/posture").mock(return_value=httpx.Response(200, json=POSTURE))
    r = runner.invoke(app, ["posture", "--api", API])
    assert r.exit_code == 0
    assert "sample-coordinator-keys" in r.output


@respx.mock
def test_posture_active_scan_uses_bearer_from_env(monkeypatch):
    monkeypatch.setenv("WITNESS_POSTURE_TOKEN", "s3cret-posture")
    route = respx.post(f"{API}/posture/scan").mock(return_value=httpx.Response(200, json=POSTURE))
    r = runner.invoke(app, ["posture", "--api", API, "--active"])
    assert r.exit_code == 0, r.output
    req = route.calls.last.request
    assert req.headers["authorization"] == "Bearer s3cret-posture"
    assert req.url.params["active"] == "true"
    assert "s3cret-posture" not in r.output


@respx.mock
def test_posture_scan_without_token_fails_before_network():
    route = respx.post(f"{API}/posture/scan").mock(return_value=httpx.Response(200, json=POSTURE))
    r = runner.invoke(app, ["posture", "--api", API, "--scan"])
    assert r.exit_code == 3
    assert "WITNESS_POSTURE_TOKEN" in r.output
    assert not route.called


@respx.mock
def test_posture_token_file(tmp_path):
    tok = tmp_path / "tok"
    tok.write_text("from-file\n", encoding="utf-8")
    route = respx.post(f"{API}/posture/scan").mock(return_value=httpx.Response(200, json=POSTURE))
    r = runner.invoke(app, ["posture", "--api", API, "--scan", "--token-file", str(tok)])
    assert r.exit_code == 0, r.output
    assert route.calls.last.request.headers["authorization"] == "Bearer from-file"


@respx.mock
def test_report_posts_range_with_bearer_and_writes_out(tmp_path, monkeypatch):
    monkeypatch.setenv("WITNESS_REPORT_TOKEN", "s3cret-report")
    result = {"reportHash": "0x" + "cd" * 32, "anchored": True, "blockId": MSG["blockId"],
              "report": {"n": 1}}
    route = respx.post(f"{API}/reports").mock(return_value=httpx.Response(201, json=result))
    out = tmp_path / "report.json"
    r = runner.invoke(app, ["report", "--api", API, "--ie", "MyDomain:fa163e5e25ef",
                            "--from", "10", "--to", "20", "--out", str(out)])
    assert r.exit_code == 0, r.output
    req = route.calls.last.request
    assert req.headers["authorization"] == "Bearer s3cret-report"
    assert json.loads(req.content) == {"ie": "MyDomain:fa163e5e25ef", "msFrom": 10, "msTo": 20}
    assert json.loads(out.read_text(encoding="utf-8")) == result
    assert result["reportHash"] in r.output
    assert "s3cret-report" not in r.output


@respx.mock
def test_report_without_token_exits_3():
    r = runner.invoke(app, ["report", "--api", API])
    assert r.exit_code == 3
    assert "WITNESS_REPORT_TOKEN" in r.output


@respx.mock
def test_report_fetch_by_hash_needs_no_token():
    h = "0x" + "cd" * 32
    respx.get(f"{API}/reports/{h}").mock(return_value=httpx.Response(
        200, json={"reportHash": h, "anchored": False, "report": {}}))
    r = runner.invoke(app, ["report", "--api", API, "--hash", h])
    assert r.exit_code == 0, r.output
    assert h in r.output


# ---------------------------------------------------------------- keys

def test_keys_gen_writes_private_prints_public_only(tmp_path):
    r = runner.invoke(app, ["keys", "gen", "relay", "--out-dir", str(tmp_path), "--json"])
    assert r.exit_code == 0, r.output
    path = tmp_path / "relay" / "sig-1.jwk.json"
    private = json.loads(path.read_text(encoding="utf-8"))
    assert private["kty"] == "OKP" and private["crv"] == "Ed25519" and "d" in private
    shown = json.loads(r.stdout)
    assert shown["kid"] == private["kid"]
    assert shown["publicJwk"]["x"] == private["x"]
    assert "d" not in shown["publicJwk"]
    assert private["d"] not in r.output
    if sys.platform != "win32":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_keys_gen_refuses_overwrite_and_keeps_file(tmp_path):
    args = ["keys", "gen", "relay", "--out-dir", str(tmp_path), "--did", "did:iota:testnet:0x5e1f"]
    first = runner.invoke(app, args)
    assert first.exit_code == 0
    path = tmp_path / "relay" / "sig-1.jwk.json"
    before = path.read_text(encoding="utf-8")
    assert "did:iota:testnet:0x5e1f#sig-1" in first.output
    second = runner.invoke(app, args)
    assert second.exit_code == 4
    assert "exists" in second.output.lower()
    assert path.read_text(encoding="utf-8") == before
    assert json.loads(before)["d"] not in second.output + first.output


def test_keys_gen_rejects_path_components(tmp_path):
    r = runner.invoke(app, ["keys", "gen", "../evil", "--out-dir", str(tmp_path)])
    assert r.exit_code == 4
