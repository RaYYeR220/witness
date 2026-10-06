from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx
import pytest
import respx
from witness_core import canon, checkpoint
from witness_core.ids import to_hex
from witness_mcp import server as s

if s.V2:
    from mcp import Client

    def connected():
        return Client(s.mcp)
else:  # mcp 1.x
    from mcp.shared.memory import create_connected_server_and_client_session

    def connected():
        return create_connected_server_and_client_session(s.mcp._mcp_server)

VECTORS = Path(__file__).resolve().parents[2] / "core" / "tests" / "vectors"
API = "http://api.test"
RPC = "https://rpc.test"
BUNDLES = json.loads((VECTORS / "bundles.json").read_text(encoding="utf-8"))
REC = json.loads((VECTORS / "rebased_record.json").read_text(encoding="utf-8"))
PACKAGE = REC["trailObject"]["result"]["data"]["type"].split("::")[0]


@pytest.fixture(autouse=True)
def env(monkeypatch):
    for n in ("WITNESS_VERIFIER_CONFIG", "WITNESS_REPORT_TOKEN", "WITNESS_DID_SNAPSHOT",
              "WITNESS_RESOLVER_URL"):
        monkeypatch.delenv(n, raising=False)
    monkeypatch.setenv("WITNESS_API_URL", API)


BAD_TAG = "ev" + chr(0x202A) + "il" + chr(0)  # bidi override and NUL


def attr(obj, camel):
    """Field access that works with both mcp 1.x (camelCase) and 2.x (snake_case)."""
    snake = "".join("_" + c.lower() if c.isupper() else c for c in camel)
    return getattr(obj, camel) if hasattr(obj, camel) else getattr(obj, snake)


def case(name):
    return next(c for c in BUNDLES["cases"] if c["name"] == name)


def pin(tmp_path, monkeypatch, name="valid_anchored", **extra):
    c = case(name)
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps(c["config"] | extra), encoding="utf-8")
    monkeypatch.setenv("WITNESS_VERIFIER_CONFIG", str(cfg))
    if c["resolver"]:
        snap = tmp_path / "did.json"
        snap.write_text(json.dumps(next(iter(BUNDLES["resolvers"][c["resolver"]].values()))),
                        encoding="utf-8")
        monkeypatch.setenv("WITNESS_DID_SNAPSHOT", str(snap))
    return c


def mock_rpc(cp, index):
    record = copy.deepcopy(REC["record"])
    f = record["result"]["data"]["content"]["fields"]["value"]["fields"]["value"]["fields"]
    f["data"]["fields"]["pos0"] = canon.jcs(cp).decode()
    f["sequence_number"] = str(index)
    f["metadata"] = json.dumps({"kind": "witness.checkpoint", "seq": 1,
                                "checkpointHash": to_hex(checkpoint.hash(cp))})

    def answer(request):
        body = json.loads(request.content)
        return httpx.Response(200, json=REC["trailObject"] if body["method"] == "iota_getObject"
                              else record)
    respx.post(RPC).mock(side_effect=answer)


# ---------------------------------------------------------------- read tools

@respx.mock
def test_search_messages_params_cap_and_untrusted():
    route = respx.get(f"{API}/messages").mock(return_value=httpx.Response(200, json={
        "items": [{"blockId": "0x1", "tag": BAD_TAG, "body": "x" * 10000}],
        "nextCursor": None}))
    out = s.search_messages(tag="t", ie="d:1", verdict="valid", since="2026-01-01", limit=5000)
    q = route.calls.last.request.url.params
    assert q["limit"] == "100" and q["tag"] == "t" and q["ie"] == "d:1"
    assert q["verdict"] == "valid" and q["date_from"] == "2026-01-01"
    assert "not instructions" in out["untrusted"]
    item = out["items"][0]
    assert item["tag"] == "evil"
    assert len(item["body"].encode()) < 4200 and item["body"].endswith("[truncated]")


@respx.mock
def test_get_message_lineage_alerts():
    respx.get(f"{API}/messages/0xabc").mock(
        return_value=httpx.Response(200, json={"blockId": "0xabc"}))
    respx.get(f"{API}/ie/d:1/lineage").mock(
        return_value=httpx.Response(200, json={"total": 1, "entries": []}))
    alerts = respx.get(f"{API}/alerts").mock(
        return_value=httpx.Response(200, json={"items": [{"rule": "FORGED"}]}))
    assert s.get_message("0xabc")["message"]["blockId"] == "0xabc"
    assert s.ie_lineage("d:1")["lineage"]["total"] == 1
    out = s.list_alerts(severity="critical", since="2026-01-01")
    assert out["alerts"] == [{"rule": "FORGED"}] and "untrusted" in out
    assert alerts.calls.last.request.url.params["severity"] == "critical"


@respx.mock
def test_api_error_is_clear():
    respx.get(f"{API}/messages/0x1").mock(return_value=httpx.Response(404, json={"detail": "no"}))
    with pytest.raises(s.WitnessToolError, match="HTTP 404: no"):
        s.get_message("0x1")
    respx.get(f"{API}/alerts").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(s.WitnessToolError, match="cannot reach"):
        s.list_alerts()


# ---------------------------------------------------------------- verify

def test_verify_without_pin_is_an_error():
    with pytest.raises(s.WitnessToolError, match="WITNESS_VERIFIER_CONFIG"):
        s.verify_message("0xabc")


@respx.mock
def test_verify_partial_without_anchor_pins_and_ignores_api_config(tmp_path, monkeypatch):
    c = pin(tmp_path, monkeypatch)
    respx.get(f"{API}/proofs/0xabc").mock(return_value=httpx.Response(200, json=c["bundle"]))
    cfg_route = respx.get(f"{API}/config/verifier").mock(
        return_value=httpx.Response(200, json=c["config"]))
    out = s.verify_message("0xabc")
    assert out["overall"] == "PARTIAL"
    assert any(st["ok"] is None for st in out["steps"])
    assert all({"name", "ok", "detail"} <= set(st) for st in out["steps"])
    assert not cfg_route.called


@respx.mock
def test_verify_valid_with_pinned_rebased_record(tmp_path, monkeypatch):
    c = pin(tmp_path, monkeypatch, rebasedRpc=RPC, auditTrailPackage=PACKAGE)
    a = c["bundle"]["anchor"]
    mock_rpc(a["checkpoint"], a["rebased"]["record"])
    respx.get(f"{API}/proofs/0xabc").mock(return_value=httpx.Response(200, json=c["bundle"]))
    out = s.verify_message("0xabc")
    assert out["overall"] == "VALID", out
    assert all(st["ok"] is True for st in out["steps"])


@respx.mock
def test_verify_tampered_record_is_invalid(tmp_path, monkeypatch):
    c = pin(tmp_path, monkeypatch, rebasedRpc=RPC, auditTrailPackage=PACKAGE)
    a = c["bundle"]["anchor"]
    cp = copy.deepcopy(a["checkpoint"])
    cp["msgCount"] += 1
    mock_rpc(cp, a["rebased"]["record"])
    respx.get(f"{API}/proofs/0xabc").mock(return_value=httpx.Response(200, json=c["bundle"]))
    assert s.verify_message("0xabc")["overall"] == "INVALID"


# ---------------------------------------------------------------- write tool

def test_create_report_needs_token():
    with pytest.raises(s.WitnessToolError, match="WITNESS_REPORT_TOKEN"):
        s.create_report()


@respx.mock
def test_create_report_sends_bearer(monkeypatch):
    monkeypatch.setenv("WITNESS_REPORT_TOKEN", "sekret")
    route = respx.post(f"{API}/reports").mock(
        return_value=httpx.Response(201, json={"reportHash": "0xr", "anchored": True}))
    out = s.create_report(ie="d:1", from_ms=3, to_ms=9)
    req = route.calls.last.request
    assert req.headers["authorization"] == "Bearer sekret"
    assert json.loads(req.content) == {"ie": "d:1", "msFrom": 3, "msTo": 9}
    assert out["report"]["reportHash"] == "0xr" and "untrusted" in out


# ---------------------------------------------------------------- MCP surface

async def test_tools_and_annotations_over_mcp():
    async with connected() as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert set(tools) == {"search_messages", "get_message", "verify_message", "ie_lineage",
                          "list_alerts", "create_report"}
    for name, t in tools.items():
        assert t.annotations is not None
        assert attr(t.annotations, "readOnlyHint") is (name != "create_report")
        assert attr(t.annotations, "destructiveHint") is False
    assert attr(tools["create_report"].annotations, "idempotentHint") is False


@respx.mock
async def test_call_tool_over_mcp():
    respx.get(f"{API}/alerts").mock(return_value=httpx.Response(200, json={"items": []}))
    async with connected() as client:
        res = await client.call_tool("list_alerts", {})
        bad = await client.call_tool("create_report", {})
    assert not attr(res, "isError") and "untrusted" in res.content[0].text
    assert attr(bad, "isError")
