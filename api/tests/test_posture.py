"""Node posture scanner: each finding fires on a vulnerable mock node and none (bar the
always-on legacy relay note) on a hardened one; passive scans never POST or attempt a login."""

import httpx
import pytest
import respx
from conftest import PG, TOKEN
from witness_api import posture
from witness_api.app import create_app
from witness_api.settings import Settings

NODE = "http://127.0.0.1:14265"
DASH = "http://127.0.0.1:8081"
NON_LOOPBACK = "http://node.example:14265"

SAMPLE_KEYS = ["0x" + k for k in sorted(posture.SAMPLE_COORDINATOR_KEYS)]
FRESH_KEYS = ["0x" + "11" * 32, "0x" + "22" * 32]

PLAINTEXT_SOME = {"total": 10, "plaintext": 7, "encrypted": 3, "ratio": 0.7}
PLAINTEXT_NONE = {"total": 10, "plaintext": 0, "encrypted": 10, "ratio": 0.0}


async def _true_probe(addr, timeout_s):
    return True


async def _false_probe(addr, timeout_s):
    return False


def _mock_vulnerable(mock):
    mock.get(f"{NODE}/api/core/v2/peers").respond(200, json=[])
    mock.get(f"{NODE}/api/core/v2/control/database/prune").respond(405)
    mock.post(f"{NODE}/api/core/v2/control/database/prune").respond(400, json={})
    mock.get(f"{NODE}/api/debug/v1/requests").respond(200, json={"requests": []})
    mock.get(f"{DASH}/dashboard/").respond(200, headers={"set-cookie": "_csrf=tok; Path=/"})
    mock.post(f"{DASH}/dashboard/auth").respond(200, json={"jwt": "SECRET-NOT-RECORDED"})


def _mock_hardened(mock):
    mock.get(f"{NODE}/api/core/v2/peers").respond(401)
    mock.get(f"{NODE}/api/core/v2/control/database/prune").respond(401)
    mock.post(f"{NODE}/api/core/v2/control/database/prune").respond(401)
    mock.get(f"{NODE}/api/debug/v1/requests").respond(404)
    mock.get(f"{DASH}/dashboard/").respond(200, headers={"set-cookie": "_csrf=tok; Path=/"})
    mock.post(f"{DASH}/dashboard/auth").respond(401, json={"error": "Unauthorized"})


async def test_every_finding_fires_on_a_vulnerable_node():
    async with respx.mock(assert_all_called=False) as mock:
        _mock_vulnerable(mock)
        async with httpx.AsyncClient() as http:
            findings = await posture.scan(
                http=http, node_url=NODE, inx_addr="127.0.0.1:9029", dashboard_url=DASH,
                config_keys=SAMPLE_KEYS, plaintext=PLAINTEXT_SOME, active=True,
                tcp_probe=_true_probe)
    ids = {f.id for f in findings}
    assert ids == {"sample-coordinator-keys", "unauthenticated-admin-routes",
                   "inx-unauthenticated", "debug-api-enabled", "dashboard-default-credentials",
                   "legacy-relay-ssrf", "plaintext-payloads"}
    # highest severity first, and every finding carries a constructive fix
    assert findings[0].severity == "high"
    assert all(f.fix for f in findings)
    # the dashboard session token is never recorded in the evidence
    dash = next(f for f in findings if f.id == "dashboard-default-credentials")
    assert "SECRET-NOT-RECORDED" not in repr(dash.evidence)


async def test_no_findings_on_a_hardened_node():
    async with respx.mock(assert_all_called=False) as mock:
        _mock_hardened(mock)
        async with httpx.AsyncClient() as http:
            findings = await posture.scan(
                http=http, node_url=NODE, inx_addr="127.0.0.1:9029", dashboard_url=DASH,
                config_keys=FRESH_KEYS, plaintext=PLAINTEXT_NONE, active=True,
                tcp_probe=_false_probe)
    # only the always-on informational note about the upstream Messages API remains
    assert {f.id for f in findings} == {"legacy-relay-ssrf"}


async def test_passive_scan_makes_no_post_or_login():
    async with respx.mock(assert_all_called=False) as mock:
        _mock_vulnerable(mock)
        async with httpx.AsyncClient() as http:
            findings = await posture.scan(
                http=http, node_url=NODE, inx_addr="127.0.0.1:9029", dashboard_url=DASH,
                config_keys=SAMPLE_KEYS, plaintext=PLAINTEXT_SOME, active=False,
                tcp_probe=_true_probe)
        methods = {call.request.method for call in mock.calls}
        urls = [str(call.request.url) for call in mock.calls]
    assert "POST" not in methods, methods
    assert not any("/dashboard/" in u for u in urls), urls
    # the admin-route finding still fires: a passive GET on a public prune route reveals it
    assert "unauthenticated-admin-routes" in {f.id for f in findings}
    assert "dashboard-default-credentials" not in {f.id for f in findings}


async def test_active_refused_against_non_loopback_host():
    async with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{NON_LOOPBACK}/api/core/v2/peers").respond(200, json=[])
        mock.get(f"{NON_LOOPBACK}/api/core/v2/control/database/prune").respond(405)
        mock.get(f"{NON_LOOPBACK}/api/debug/v1/requests").respond(404)
        async with httpx.AsyncClient() as http:
            await posture.scan(
                http=http, node_url=NON_LOOPBACK, inx_addr=None, dashboard_url=None,
                config_keys=FRESH_KEYS, plaintext=PLAINTEXT_NONE, active=True,
                tcp_probe=_false_probe)
        methods = {call.request.method for call in mock.calls}
    assert "POST" not in methods  # active probe refused: host is not loopback/allow-listed


async def test_active_allowed_when_host_is_allow_listed():
    assert posture.host_allowed("node.example", frozenset({"node.example"}))
    assert posture.host_allowed("127.0.0.1", frozenset())
    assert not posture.host_allowed("node.example", frozenset())


def test_sample_key_match_is_case_and_prefix_insensitive():
    assert posture.check_sample_keys(["ED3C3F1A319FF4E909CF2771D79FECE0AC9BD9FD2EE49EA6C0885C9CB3B1248C"])
    assert posture.check_sample_keys(SAMPLE_KEYS).severity == "high"
    assert posture.check_sample_keys(FRESH_KEYS) is None


# -- the route, against the test database ----------------------------------------------------

def _settings(store) -> Settings:
    # inx_addr is None so the route test does no real TCP probe (respx cannot mock one).
    return Settings(db=PG, schema=store.schema, coordinator_keys=SAMPLE_KEYS, threshold=2,
                    hornet_url=NODE, inx_addr=None, posture_dashboard_url=DASH,
                    posture_token=TOKEN, validate=False)


@pytest.fixture
async def posture_client(store):
    app = create_app(_settings(store), store=store)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://witness.test") as c:
            yield c


async def test_scan_requires_token_and_caches(posture_client, store):
    # no token: 401; GET /posture before any scan is empty
    assert (await posture_client.post("/posture/scan")).status_code == 401
    empty = await posture_client.get("/posture")
    assert empty.status_code == 200 and empty.json()["scannedAtMs"] is None

    async with respx.mock(assert_all_called=False) as mock:
        _mock_vulnerable(mock)
        # the store-backed INX probe is real; point it nowhere reachable so it just returns
        r = await posture_client.post("/posture/scan",
                                      headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scannedAtMs"] is not None
    ids = {f["id"] for f in body["findings"]}
    assert "sample-coordinator-keys" in ids and "legacy-relay-ssrf" in ids
    assert body["summary"].get("high", 0) >= 1
    # GET /posture now returns the cached scan
    cached = await posture_client.get("/posture")
    assert cached.json()["scannedAtMs"] == body["scannedAtMs"]
