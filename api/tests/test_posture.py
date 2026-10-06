"""Node posture scanner: each finding fires on a vulnerable mock node and none (bar the
always-on legacy relay note) on a hardened one; passive scans never POST or attempt a login;
ambiguous answers are reported as inconclusive, never as exposure; active probes stay on
loopback or allow-listed hosts."""

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
FOREIGN_DASH = "http://dash.example:8081"
PEERS = "/api/core/v2/peers"
PRUNE = "/api/core/v2/control/database/prune"
DEBUG = "/api/debug/v1/requests"

SAMPLE_KEYS = ["0x" + k for k in sorted(posture.SAMPLE_COORDINATOR_KEYS)]
FRESH_KEYS = ["0x" + "11" * 32, "0x" + "22" * 32]

PLAINTEXT_SOME = {"total": 10, "plaintext": 7, "encrypted": 3, "ratio": 0.7}
PLAINTEXT_NONE = {"total": 10, "plaintext": 0, "encrypted": 10, "ratio": 0.0}


async def _true_probe(addr, timeout_s):
    return True


async def _false_probe(addr, timeout_s):
    return False


def _mock_node(mock, base=NODE, *, peers=200, prune_get=405, prune_post=400, debug=200):
    for path, method, status in ((PEERS, "GET", peers), (PRUNE, "GET", prune_get),
                                 (PRUNE, "POST", prune_post), (DEBUG, "GET", debug)):
        route = mock.route(method=method, url=base + path)
        if isinstance(status, Exception):
            route.mock(side_effect=status)
        else:
            route.respond(status)


def _mock_dashboard(mock, base=DASH, *, auth=200):
    mock.get(f"{base}/dashboard/").respond(200, headers={"set-cookie": "_csrf=tok; Path=/"})
    mock.post(f"{base}/dashboard/auth").respond(auth, json={"jwt": "SECRET-NOT-RECORDED"})


async def _scan(**kw):
    args = {"node_url": NODE, "inx_addr": "127.0.0.1:9029", "dashboard_url": DASH,
                "config_keys": FRESH_KEYS, "plaintext": PLAINTEXT_NONE, "active": False,
                "tcp_probe": _false_probe}
    args.update(kw)
    async with httpx.AsyncClient() as http:
        return await posture.scan(http=http, **args)


def _ids(findings):
    return {f.id for f in findings}


def _methods(mock):
    return [(c.request.method, c.request.url.host, c.request.url.path) for c in mock.calls]


# -- every finding fires / none fires ---------------------------------------------------------

async def test_every_finding_fires_on_a_vulnerable_node():
    async with respx.mock(assert_all_called=False) as mock:
        _mock_node(mock)
        _mock_dashboard(mock)
        findings = await _scan(config_keys=SAMPLE_KEYS, plaintext=PLAINTEXT_SOME, active=True,
                               tcp_probe=_true_probe)
    assert _ids(findings) == {"sample-coordinator-keys", "unauthenticated-admin-routes",
                              "inx-unauthenticated", "debug-api-enabled",
                              "dashboard-default-credentials", "legacy-relay-ssrf",
                              "plaintext-payloads"}
    assert findings[0].severity == "high"
    assert all(f.fix for f in findings)
    dash = next(f for f in findings if f.id == "dashboard-default-credentials")
    assert "SECRET-NOT-RECORDED" not in repr(dash.evidence)
    admin = next(f for f in findings if f.id == "unauthenticated-admin-routes")
    assert admin.evidence["prune"] == {"method": "POST", "status": 400, "result": "open"}


async def test_no_findings_on_a_hardened_node():
    async with respx.mock(assert_all_called=False) as mock:
        _mock_node(mock, peers=401, prune_get=401, prune_post=401, debug=404)
        _mock_dashboard(mock, auth=401)
        findings = await _scan(active=True)
    # only the always-on informational note about the upstream Messages API remains
    assert _ids(findings) == {"legacy-relay-ssrf"}


async def test_passive_scan_makes_no_post_or_login():
    async with respx.mock(assert_all_called=False) as mock:
        _mock_node(mock)
        _mock_dashboard(mock)
        findings = await _scan(config_keys=SAMPLE_KEYS, plaintext=PLAINTEXT_SOME,
                               tcp_probe=_true_probe)
        calls = _methods(mock)
    assert all(method != "POST" for method, _, _ in calls), calls
    assert not any(path.startswith("/dashboard") for _, _, path in calls), calls
    # peers 200 and prune GET 405: the admin-route finding fires on passive evidence
    admin = next(f for f in findings if f.id == "unauthenticated-admin-routes")
    assert admin.evidence["prune"] == {"method": "GET", "status": 405, "result": "open"}
    assert "dashboard-default-credentials" not in _ids(findings)


# -- inconclusive passive answers ----------------------------------------------------------

@pytest.mark.parametrize("peers,prune_get", [
    (404, 404),          # routes not there (another node, a proxy)
    (503, 500),          # node errors
    (401, 405),          # prune 405 proves nothing while peers is protected
    (404, 405),
    (httpx.ConnectError("down"), httpx.ConnectError("down")),
])
async def test_ambiguous_passive_answers_are_inconclusive(peers, prune_get):
    async with respx.mock(assert_all_called=False) as mock:
        _mock_node(mock, peers=peers, prune_get=prune_get, debug=404)
        findings = await _scan()
    assert "unauthenticated-admin-routes" not in _ids(findings)
    inc = next(f for f in findings if f.id == "admin-routes-inconclusive")
    assert inc.severity == "info"
    assert inc.evidence["peers"]["result"] in ("inconclusive", "protected")
    assert inc.evidence["prune"]["result"] == "inconclusive"
    expected = None if isinstance(peers, Exception) else peers
    assert inc.evidence["peers"]["status"] == expected


async def test_open_peers_alone_is_exposure():
    async with respx.mock(assert_all_called=False) as mock:
        _mock_node(mock, peers=200, prune_get=404, debug=404)
        findings = await _scan()
    admin = next(f for f in findings if f.id == "unauthenticated-admin-routes")
    assert admin.evidence["peers"]["result"] == "open"
    assert admin.evidence["prune"]["result"] == "inconclusive"


# -- the active gate ----------------------------------------------------------------------------

def test_loopback_and_allow_list_matching():
    for host in ("localhost", "LOCALHOST", "127.0.0.1", "127.0.0.2", "::1", "[::1]"):
        assert posture.host_allowed(host, frozenset()), host
    for host in ("", "0.0.0.0", "node.example", "localhost.example", "127.0.0.1.example",
                 "10.0.0.1"):
        assert not posture.host_allowed(host, frozenset()), host
    assert posture.host_allowed("node.example", frozenset({"Node.Example"}))
    assert not posture.host_allowed("sub.node.example", frozenset({"node.example"}))


@pytest.mark.parametrize("base", ["http://localhost:14265", "http://[::1]:14265"])
async def test_active_probes_run_on_localhost_and_ipv6_loopback(base):
    async with respx.mock(assert_all_called=False) as mock:
        _mock_node(mock, base=base)
        await _scan(node_url=base, dashboard_url=None, active=True)
        calls = _methods(mock)
    assert ("POST", base.split("//")[1].rsplit(":", 1)[0].strip("[]"), PRUNE) in calls


async def test_active_refused_against_non_loopback_node():
    async with respx.mock(assert_all_called=False) as mock:
        _mock_node(mock, base=NON_LOOPBACK)
        await _scan(node_url=NON_LOOPBACK, dashboard_url=None, active=True)
        calls = _methods(mock)
    assert all(method != "POST" for method, _, _ in calls), calls


async def test_active_skips_a_non_allowed_dashboard_host():
    async with respx.mock(assert_all_called=False) as mock:
        _mock_node(mock)
        _mock_dashboard(mock, base=FOREIGN_DASH)
        findings = await _scan(dashboard_url=FOREIGN_DASH, active=True)
        calls = _methods(mock)
    # the loopback node still gets its active probe; the foreign dashboard is never touched
    assert ("POST", "127.0.0.1", PRUNE) in calls
    assert not any(host == "dash.example" for _, host, _ in calls), calls
    assert "dashboard-default-credentials" not in _ids(findings)


async def test_allow_listed_dashboard_host_is_probed():
    async with respx.mock(assert_all_called=False) as mock:
        _mock_node(mock)
        _mock_dashboard(mock, base=FOREIGN_DASH)
        findings = await _scan(dashboard_url=FOREIGN_DASH, active=True,
                               allow_active_hosts=("dash.example",))
    assert "dashboard-default-credentials" in _ids(findings)


async def test_dashboard_probe_leaves_no_cookies_in_the_shared_client():
    async with respx.mock(assert_all_called=False) as mock:
        _mock_node(mock)
        _mock_dashboard(mock)
        async with httpx.AsyncClient() as http:
            await posture.scan(http=http, node_url=NODE, inx_addr=None, dashboard_url=DASH,
                               config_keys=FRESH_KEYS, active=True, tcp_probe=_false_probe)
            assert "_csrf" not in http.cookies


def test_sample_key_match_is_case_and_prefix_insensitive():
    assert posture.check_sample_keys(
        ["ED3C3F1A319FF4E909CF2771D79FECE0AC9BD9FD2EE49EA6C0885C9CB3B1248C"])
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


async def test_scan_requires_token_and_caches(posture_client):
    assert (await posture_client.post("/posture/scan")).status_code == 401
    empty = await posture_client.get("/posture")
    assert empty.status_code == 200 and empty.json()["scannedAtMs"] is None

    async with respx.mock(assert_all_called=False) as mock:
        _mock_node(mock)
        r = await posture_client.post("/posture/scan",
                                      headers={"Authorization": f"Bearer {TOKEN}"})
        assert all(c.request.method != "POST" for c in mock.calls)  # passive by default
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scannedAtMs"] is not None and body["active"] is False
    ids = {f["id"] for f in body["findings"]}
    assert {"sample-coordinator-keys", "unauthenticated-admin-routes",
            "legacy-relay-ssrf"} <= ids
    assert body["summary"]["high"] >= 2
    cached = await posture_client.get("/posture")
    assert cached.json() == body
