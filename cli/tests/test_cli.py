"""The witness CLI: exit codes of the offline verifier and the query commands."""

from __future__ import annotations

import copy
import json
import stat
import sys
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner
from witness_cli.main import app
from witness_core import canon, checkpoint
from witness_core.ids import to_hex

VECTORS = Path(__file__).resolve().parents[2] / "core" / "tests" / "vectors" / "bundles.json"
API = "http://api.test"
RPC = "https://rpc.test"
RESOLVER = "http://resolver.test"

runner = CliRunner()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("WITNESS_API_URL", "WITNESS_REBASED_RPC", "WITNESS_RESOLVER_URL",
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
    # Past the shared nesting cap (2501 levels parse with json.loads on every platform).
    deep = tmp_path / "deep.json"
    deep.write_text('{"v":1,"x":' + "[" * 2500 + "]" * 2500 + "}", encoding="utf-8")
    r = runner.invoke(app, ["verify", str(deep), "--config", str(f["config"])])
    assert r.exit_code == 4 and "nested deeper than 2500 levels" in r.output
    r = runner.invoke(app, ["verify", "-", "--config", str(f["config"])],
                      input='{"v":1,"x":' + "[" * 2500 + "]" * 2500 + "}")
    assert r.exit_code != 0 and "nested deeper than 2500 levels" in r.output


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


# ---------------------------------------------------------------- step 5 via the Rebased RPC

REC = json.loads((VECTORS.parent / "rebased_record.json").read_text(encoding="utf-8"))
PACKAGE = REC["trailObject"]["result"]["data"]["type"].split("::")[0]
WRITER = "0xd40892daf5c81e3d67ffe9806575970b973ecf6625eb8a88562afae0d8c940c8"


def rpc_record(cp: dict, index: int) -> dict:
    record = copy.deepcopy(REC["record"])
    f = record["result"]["data"]["content"]["fields"]["value"]["fields"]["value"]["fields"]
    f["data"]["fields"]["pos0"] = canon.jcs(cp).decode()
    f["sequence_number"] = str(index)
    f["metadata"] = json.dumps({"kind": "witness.checkpoint", "seq": 1,
                                "checkpointHash": to_hex(checkpoint.hash(cp))})
    return record


def mock_rpc(record: dict, calls: list | None = None, url: str = RPC):
    def answer(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if calls is not None:
            calls.append(body)
        doc = REC["trailObject"] if body["method"] == "iota_getObject" else record
        return httpx.Response(200, json=doc)
    return respx.post(url).mock(side_effect=answer)


def pinned_config(tmp_path, vectors, **extra) -> Path:
    cfg = case(vectors, "valid_anchored")["config"] | {
        "rebasedRpc": RPC, "auditTrailPackage": PACKAGE} | extra
    path = tmp_path / "pinned.config.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return path


def bundle_of(f) -> dict:
    return json.loads(f["bundle"].read_text(encoding="utf-8"))


def verify_args(f, cfg) -> list[str]:
    return ["verify", str(f["bundle"]), "--config", str(cfg), "--did-snapshot", str(f["snapshot"])]


@respx.mock
def test_verify_valid_with_chain_record_from_pinned_rpc(files, vectors, tmp_path):
    f = files("valid_anchored")
    a = bundle_of(f)["anchor"]
    calls: list = []
    mock_rpc(rpc_record(a["checkpoint"], a["rebased"]["record"]), calls)
    r = runner.invoke(app, verify_args(f, pinned_config(tmp_path, vectors)))
    assert r.exit_code == 0, r.output
    assert [c["method"] for c in calls] == ["iota_getObject", "iotax_getDynamicFieldObject"]
    assert calls[0]["params"][0] == case(vectors, "valid_anchored")["config"]["trailId"]


@respx.mock
def test_verify_tampered_chain_record_is_invalid(files, vectors, tmp_path):
    f = files("valid_anchored")
    a = bundle_of(f)["anchor"]
    cp = copy.deepcopy(a["checkpoint"])
    cp["msgCount"] += 1
    mock_rpc(rpc_record(cp, a["rebased"]["record"]))
    r = runner.invoke(app, verify_args(f, pinned_config(tmp_path, vectors)))
    assert r.exit_code == 1, r.output


@respx.mock
def test_verify_missing_record_and_rpc_failure_are_partial(files, vectors, tmp_path):
    f = files("valid_anchored")
    args = verify_args(f, pinned_config(tmp_path, vectors))
    mock_rpc({"jsonrpc": "2.0", "id": 1, "result": {"error": {"code": "dynamicFieldNotFound"}}})
    assert runner.invoke(app, args).exit_code == 2
    respx.reset()
    respx.post(RPC).mock(return_value=httpx.Response(503))
    assert runner.invoke(app, args).exit_code == 2


@respx.mock
def test_verify_wrong_writer_pin_is_invalid(files, vectors, tmp_path):
    f = files("valid_anchored")
    a = bundle_of(f)["anchor"]
    mock_rpc(rpc_record(a["checkpoint"], a["rebased"]["record"]))
    bad = pinned_config(tmp_path, vectors, anchorWriter="0x" + "ee" * 32)
    assert runner.invoke(app, verify_args(f, bad)).exit_code == 1
    good = pinned_config(tmp_path, vectors, anchorWriter=WRITER)
    assert runner.invoke(app, verify_args(f, good)).exit_code == 0


@respx.mock
def test_verify_rpc_override_no_anchor_and_plain_http(files, vectors, tmp_path):
    f = files("valid_anchored")
    a = bundle_of(f)["anchor"]
    base = verify_args(f, pinned_config(tmp_path, vectors))
    record = rpc_record(a["checkpoint"], a["rebased"]["record"])
    route = mock_rpc(record)
    assert runner.invoke(app, [*base, "--no-anchor"]).exit_code == 2
    assert not route.called
    # plain http is refused unless explicitly allowed; the refusal is PARTIAL, not a crash
    assert runner.invoke(app, [*base, "--rebased-rpc", "http://rpc.test"]).exit_code == 2
    mock_rpc(record, url="http://rpc.test")
    assert runner.invoke(app, [*base, "--rebased-rpc", "http://rpc.test",
                               "--insecure-rpc"]).exit_code == 0


def test_verify_warns_on_plain_http_resolver(files):
    f = files("valid_anchored")
    r = runner.invoke(app, ["verify", str(f["bundle"]), "--config", str(f["config"]),
                            "--resolver", "http://resolver.test"])
    assert "plain http" in r.output


# ---------------------------------------------------------------- output injection

EVIL = "[/x][link=http://e]x\x1b]8;;\x9b31m[bold red]\x07"


def assert_clean(r) -> None:
    assert "\x1b" not in r.output and "\x9b" not in r.output and "\x07" not in r.output
    assert "MarkupError" not in r.output and "Traceback" not in r.output


def test_ladder_detail_cannot_inject(files, tmp_path):
    f = files("valid_anchored")
    b = bundle_of(f)
    b["envelope"]["didDoc"] = {"doc": {"id": EVIL}, "keys": []}
    b["network"] = EVIL  # lands in a step detail ("does not match pinned")
    path = tmp_path / "evil.bundle.json"
    path.write_text(json.dumps(b), encoding="utf-8")
    r = runner.invoke(app, ["verify", str(path), "--config", str(f["config"]),
                            "--did-snapshot", str(f["snapshot"])])
    assert r.exit_code == 1
    assert_clean(r)
    assert "INVALID" in r.output


@respx.mock
def test_search_row_and_error_body_cannot_inject():
    row = MSG | {"tag": EVIL, "iss": EVIL, "ieId": EVIL}
    respx.get(f"{API}/messages").mock(return_value=httpx.Response(
        200, json={"items": [row], "nextCursor": EVIL, "limit": 50}))
    r = runner.invoke(app, ["search", "--api", API])
    assert r.exit_code == 0
    assert "[/x][link=http://e]x" in r.output  # shown literally, never interpreted
    assert_clean(r)
    respx.reset()
    respx.get(f"{API}/messages").mock(return_value=httpx.Response(400, json={"detail": EVIL}))
    r = runner.invoke(app, ["search", "--api", API])
    assert r.exit_code == 4
    assert_clean(r)


@respx.mock
def test_posture_hostile_fields_are_plain_and_json_is_ascii():
    doc = POSTURE | {"findings": [{"id": EVIL, "severity": EVIL, "title": EVIL,
                                   "evidence": {}, "fix": EVIL}]}
    respx.get(f"{API}/posture").mock(return_value=httpx.Response(200, json=doc))
    r = runner.invoke(app, ["posture", "--api", API])
    assert r.exit_code == 0
    assert_clean(r)
    r = runner.invoke(app, ["posture", "--api", API, "--json"])
    assert r.exit_code == 0
    assert_clean(r)
    assert json.loads(r.stdout) == doc


@respx.mock
def test_search_sends_milestone_range():
    route = respx.get(f"{API}/messages").mock(return_value=httpx.Response(
        200, json={"items": [], "nextCursor": None, "limit": 50}))
    r = runner.invoke(app, ["search", "--api", API, "--ms-from", "5", "--ms-to", "9"])
    assert r.exit_code == 0
    q = dict(route.calls.last.request.url.params)
    assert q["ms_from"] == "5" and q["ms_to"] == "9"


def test_unicode_format_chars_and_newlines_are_stripped(files, tmp_path):
    from witness_cli.main import strip_ctrl

    assert strip_ctrl("a\u202eb\u200bc\ufeffd\u2028e\nf\tg\u2066") == "abcd e f g"
    f = files("valid_anchored")
    b = bundle_of(f)
    b["network"] = "evil\u202enet\nFORGED VALID"
    path = tmp_path / "bidi.bundle.json"
    path.write_text(json.dumps(b), encoding="utf-8")
    r = runner.invoke(app, ["verify", str(path), "--config", str(f["config"])])
    assert r.exit_code == 1
    assert "\u202e" not in r.output
    assert not any(line.strip() == "FORGED VALID" for line in r.output.splitlines())


@respx.mock
def test_search_row_strips_bidi_and_newlines():
    row = MSG | {"tag": "x\u202ey\nVALID\u2029z"}
    respx.get(f"{API}/messages").mock(return_value=httpx.Response(
        200, json={"items": [row], "nextCursor": None, "limit": 50}))
    r = runner.invoke(app, ["search", "--api", API])
    assert "\u202e" not in r.output and "\u2029" not in r.output
    assert "xy VALID z" in r.output


@respx.mock
def test_rpc_override_is_announced_on_stderr(files, vectors, tmp_path):
    f = files("valid_anchored")
    mock_rpc({"jsonrpc": "2.0", "id": 1, "result": {"error": {"code": "dynamicFieldNotFound"}}},
             url="https://other.test")
    r = runner.invoke(app, [*verify_args(f, pinned_config(tmp_path, vectors)),
                            "--rebased-rpc", "https://other.test"])
    assert "instead of the pinned https://rpc.test" in r.output
    mock_rpc({"jsonrpc": "2.0", "id": 1, "result": {"error": {"code": "dynamicFieldNotFound"}}})
    quiet = runner.invoke(app, [*verify_args(f, pinned_config(tmp_path, vectors)),
                                "--rebased-rpc", RPC])
    assert "instead of" not in quiet.output
