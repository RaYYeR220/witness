"""The relay must stay a drop-in for eclipse-aerios/iota-messages-api."""

import json

import httpx
from witness_core import verdicts


def _vector(helpers):
    return json.loads((helpers.vectors / "legacy_upload_response.json").read_text())


async def test_legacy_contract_golden(make_cfg, hornet, relay, helpers):
    vec = _vector(helpers)
    legacy_body = vec["bodyUtf8"]
    # HORNET answers with exactly the text the legacy relay wrapped in the vector.
    hornet_text = json.loads(legacy_body)["return_payload"]
    hornet.route.mock(
        side_effect=lambda request: httpx.Response(
            201, text=hornet_text, headers={"content-type": "application/json"}
        )
    )

    async with relay(make_cfg()) as client:
        resp = await client.post("/upload", params={"node": "iota-hornet"}, json=vec["request"])

        assert resp.status_code == vec["status"] == 200
        assert resp.headers["content-type"].startswith("application/json")
        body = resp.json()
        assert set(body) == {"status_code", "return_payload", "witness"}
        # Same bytes as the legacy relay up to the additive `witness` field ...
        legacy_prefix = legacy_body[: -len("\n}\n")]
        assert resp.text.startswith(legacy_prefix + ',\n  "witness": {')
        # ... and dropping it reproduces the captured response byte for byte.
        legacy_only = {k: body[k] for k in ("status_code", "return_payload")}
        rendered = json.dumps(legacy_only, indent=2, sort_keys=True) + "\n"
        assert rendered.encode() == bytes.fromhex(vec["bodyHex"])
        assert body["witness"]["blockId"] == json.loads(hornet_text)["blockId"]
        assert body["witness"]["verdict"] == verdicts.RELAY_ATTESTED

        # Refusal: signature required, no grace, anonymous caller.
        refused = await client.post(
            "/upload", params={"node": "iota-hornet"}, json={"tag": "locked", "message": {"a": 1}}
        )
        assert refused.status_code == 403
        assert refused.json()["verdict"] == verdicts.UNAUTHORIZED_WRITER
        assert refused.json()["error"]

        unknown = await client.post(
            "/upload", params={"node": "nope"}, json={"tag": "trust.score", "message": {}}
        )
        assert unknown.status_code == 400
        assert unknown.json() == {"error": "unknown node"}


async def test_hornet_unreachable_keeps_legacy_text(make_cfg, hornet, relay):
    hornet.state.error = httpx.ConnectError("connection refused")
    async with relay(make_cfg()) as client:
        resp = await client.post(
            "/upload", params={"node": "iota-hornet"}, json={"tag": "trust.score", "message": {}}
        )
    assert resp.status_code == 400
    assert resp.text == "Hornet node not found, check that the Hornet node exists.\n"


async def test_hornet_error_is_502_with_body(make_cfg, hornet, relay):
    hornet.state.status = 400
    async with relay(make_cfg()) as client:
        resp = await client.post(
            "/upload", params={"node": "iota-hornet"}, json={"tag": "trust.score", "message": {}}
        )
    assert resp.status_code == 502
    body = resp.json()
    assert body["status_code"] == 400
    assert "invalid block" in body["return_payload"]
    assert body["witness"]["blockId"] is None


async def test_malformed_request_is_400(make_cfg, hornet, relay):
    async with relay(make_cfg()) as client:
        for content in (b"not json", b"[]", b'{"message": {}}', b'{"tag": 5, "message": {}}'):
            resp = await client.post("/upload", params={"node": "iota-hornet"}, content=content)
            assert resp.status_code == 400, content
    assert hornet.route.call_count == 0
