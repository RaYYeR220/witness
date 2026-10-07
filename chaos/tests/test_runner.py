"""The fault-injection runner, offline: the explorer API, relay and Orion are mocked."""

import base64
import json
import shutil
from pathlib import Path

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from helpers import cls
from witness_chaos import attacks as A
from witness_chaos import runner as R
from witness_chaos import traffic as T
from witness_core import sealed as S

API = "http://api.test"
BID = "0x" + "ab" * 32
REPO = Path(__file__).resolve().parents[2]
CLI = REPO / "packages" / "verify" / "dist" / "cli.js"
HAVE_TS = CLI.exists() and shutil.which("node") is not None


class Clock:
    def __init__(self, start: int = 1_800_000_000_000) -> None:
        self.ms = start

    def __call__(self) -> int:
        return self.ms

    async def sleep(self, s: float) -> None:
        self.ms += int(s * 1000)


def rec(cid: str, block_id: str | None = BID, ie: str | None = None, at: int = 1_800_000_000_000,
        **detail) -> A.InjectionRecord:
    return A.InjectionRecord(cid, block_id, ie, A.expected_for(cid), at, detail)


def alert(i: int, rule: str, sev: str, at: int, block_id=BID, ie=None) -> dict:
    return {"id": i, "rule": rule, "severity": sev, "blockId": block_id, "ieId": ie,
            "atMs": at, "evidence": {}}


async def run_observe(key, cid, r, clock, **kw):
    async with httpx.AsyncClient() as http:
        return await R.observe(R.ExplorerApi(API, http), cls(key, cid), r,
                               trial_start_ms=r.injected_at_ms - 100,
                               timeout_s=cls(key, cid)["timeout_s"], poll_s=1.0,
                               clock_ms=clock, sleep=clock.sleep, **kw)


# ---------------------------------------------------------------------------- observing


@respx.mock
async def test_verdict_class_detected_on_a_later_poll(key):
    clock = Clock()
    replies = iter([httpx.Response(404), httpx.Response(200, json={"indexed": False}),
                    httpx.Response(200, json={"verdict": "FORGED", "indexed": True})])
    respx.get(f"{API}/messages/{BID}").mock(side_effect=lambda r: next(replies))
    respx.get(f"{API}/alerts").mock(return_value=httpx.Response(200, json={"items": [
        alert(1, "SHADOW", "high", clock.ms + 500)]}))
    r = rec("A01", at=clock.ms)
    o = await run_observe(key, "A01", r, clock, by_ie=False)
    assert o.detected and o.polls == 3 and o.verdict == "FORGED"
    row = R.trial_row(cls(key, "A01"), 0, r, o, trial_start_ms=r.injected_at_ms)
    assert row["detected"] and row["observed"] == "FORGED"
    assert (row["latency_ms"], row["latency_source"]) == (2000, "poll")
    assert row["alerts"] == ["SHADOW"]  # an allowed side alert, reported


@respx.mock
async def test_alert_class_uses_server_alert_time_and_the_trial_ie(key):
    clock = Clock()
    ie = "ChaosDomain:0123456789ab"
    block_q = respx.get(f"{API}/alerts", params={"block_id": BID}).mock(
        return_value=httpx.Response(200, json={"items": []}))
    ie_q = respx.get(f"{API}/alerts", params={"ie": ie}).mock(
        return_value=httpx.Response(200, json={"items": [
            alert(7, "ANOMALY", "medium", clock.ms + 4_321, ie=ie)]}))
    respx.get(f"{API}/messages/{BID}").mock(return_value=httpx.Response(
        200, json={"verdict": "PRODUCER_SIGNED", "indexed": True}))
    r = rec("A13", ie=ie, at=clock.ms)
    o = await run_observe(key, "A13", r, clock, by_ie=True)
    assert o.detected and o.polls == 1
    assert block_q.called and ie_q.called
    assert ie_q.calls[0].request.url.params["since"] == str(r.injected_at_ms - 100)
    assert R.latency(cls(key, "A13"), r, o) == (4_321, "alert.atMs")


@respx.mock
async def test_timeout_without_detection(key):
    clock = Clock()
    respx.get(f"{API}/messages/{BID}").mock(return_value=httpx.Response(
        200, json={"verdict": "PRODUCER_SIGNED", "indexed": True}))
    respx.get(f"{API}/alerts").mock(return_value=httpx.Response(200, json={"items": []}))
    r = rec("A01", at=clock.ms)
    o = await run_observe(key, "A01", r, clock, by_ie=False)
    assert not o.detected
    assert clock.ms - r.injected_at_ms == 15_000  # stopped at the class timeout
    assert o.polls == 16
    row = R.trial_row(cls(key, "A01"), 0, r, o, trial_start_ms=r.injected_at_ms)
    assert row["detected"] is False and row["observed"] == "PRODUCER_SIGNED"
    assert row["latency_ms"] is None


@respx.mock
async def test_http_errors_while_polling_are_kept_not_fatal(key):
    clock = Clock()
    respx.get(f"{API}/messages/{BID}").mock(side_effect=[
        httpx.ConnectError("api down"),
        httpx.Response(200, json={"verdict": "FORGED", "indexed": True})])
    respx.get(f"{API}/alerts").mock(return_value=httpx.Response(200, json={"items": []}))
    o = await run_observe(key, "A01", rec("A01", at=clock.ms), clock, by_ie=False)
    assert o.detected and o.polls == 2 and "ConnectError" in o.errors[0]


@respx.mock
async def test_expected_rule_with_wrong_severity_does_not_count(key):
    clock = Clock()
    respx.get(f"{API}/messages/{BID}").mock(return_value=httpx.Response(404))
    respx.get(f"{API}/alerts").mock(return_value=httpx.Response(200, json={"items": [
        alert(3, "SHADOW", "low", clock.ms + 10)]}))
    r = rec("A17", ie=None, at=clock.ms)
    o = await run_observe(key, "A17", r, clock, by_ie=False)
    assert not o.detected
    assert o.labels(cls(key, "A17")) == ["SHADOW@low"]
    assert R.alert_label(cls(key, "A01"), alert(4, "SHADOW", "low", 0)) == "SHADOW"


@respx.mock
async def test_control_watches_the_whole_window(key):
    clock = Clock()
    ctl = key["controls"][0]
    ie = "ChaosDomain:00000000000c"
    respx.get(f"{API}/messages/{BID}").mock(return_value=httpx.Response(
        200, json={"verdict": "PRODUCER_SIGNED", "indexed": True}))
    respx.get(f"{API}/alerts").mock(return_value=httpx.Response(200, json={"items": []}))
    r = rec("C01", ie=ie, at=clock.ms)
    async with httpx.AsyncClient() as http:
        o = await R.observe(R.ExplorerApi(API, http), ctl, r, trial_start_ms=r.injected_at_ms,
                            timeout_s=ctl["timeout_s"], poll_s=5.0, by_ie=True,
                            stop_on_detect=False, clock_ms=clock, sleep=clock.sleep)
    assert clock.ms - r.injected_at_ms == 90_000 and o.polls == 19
    assert not o.alerts


@respx.mock
async def test_keepalive_runs_while_waiting(key):
    clock = Clock()
    respx.get(f"{API}/alerts").mock(return_value=httpx.Response(200, json={"items": []}))
    calls = []

    async def keep():
        calls.append(clock.ms)

    r = rec("A06", block_id=None, ie="ChaosDomain:00000000000d", at=clock.ms)
    o = await run_observe(key, "A06", r, clock, by_ie=True, keepalive=keep, keepalive_s=45)
    assert not o.detected
    assert len(calls) == 5  # 240 s window, every 45 s


@respx.mock
async def test_a11_needs_sealed_storage_and_blind_lookup(key):
    clock = Clock()
    plain = {"reportId": "r1", "secret": "s0123456789abcdef"}
    kp = X25519PrivateKey.generate()
    enc = S.encrypt_body(plain, [S.Recipient("did:x#kex-1", kp.public_key().public_bytes_raw())])
    stored = {"w": 1, "tag": "audit.report", "enc": enc}
    respx.get(f"{API}/messages/{BID}").mock(return_value=httpx.Response(200, json={
        "verdict": "RELAY_ATTESTED", "indexed": True,
        "dataHex": "0x" + json.dumps(stored).encode().hex()}))
    respx.get(f"{API}/alerts").mock(return_value=httpx.Response(200, json={"items": []}))
    blind = respx.post(f"{API}/lookup/blind").mock(side_effect=[
        httpx.Response(200, json={"matches": []}),
        httpx.Response(200, json={"matches": [{"blockId": BID}]})])
    r = rec("A11", at=clock.ms, plaintext=plain, blindToken="tok")
    o = await run_observe(key, "A11", r, clock, by_ie=False)
    assert o.detected and o.sealed is True and o.blind_search is True and o.polls == 2
    assert json.loads(blind.calls[0].request.content) == {"tokens": ["tok"]}


# ---------------------------------------------------------------------------- bundles


def test_vector_bundle_is_the_test_fixture(real_bundle, cfg, sample_keys):
    b, vcfg, keys = R.vector_bundle(REPO / "core" / "tests" / "vectors")
    assert b == real_bundle
    assert vcfg == cfg and keys == sample_keys


def test_parity_compares_every_step():
    py = {"overall": "INVALID", "steps": {"block_hash": False, "inclusion": True,
                                          "milestone_signatures": True, "envelope": None,
                                          "anchor": True}}
    assert R.parity(py, {"overall": "INVALID", "steps": dict(py["steps"])}) == (True, [])
    ok, diffs = R.parity(py, {"overall": "INVALID", "steps": {**py["steps"], "anchor": None}})
    assert not ok and diffs == ["anchor: py True ts None"]
    ok, diffs = R.parity(py, {"error": "exit 3"})
    assert not ok and "TS verifier failed" in diffs[0]


def _secrets(tmp_path: Path) -> Path:
    R.write_keys(str(tmp_path / "secrets" / "chaos"), str(REPO / "chaos" / "demo-policy.json"))
    return tmp_path / "secrets"


def make_runner(tmp_path, **kw):
    cfg = R.RunConfig(api=API, relay="http://relay.test", orion="http://orion.test",
                      hornet="http://hornet.test", secrets_dir=str(_secrets(tmp_path)),
                      out=str(tmp_path / "out"), repo=str(REPO), trap=False,
                      orion_settle_s=0, **kw)
    clock = Clock()
    r = R.Runner(cfg, http=httpx.AsyncClient(), clock_ms=clock, sleep=clock.sleep)
    r.ctx = r.build_context()
    return r, clock


@pytest.mark.skipif(not HAVE_TS, reason="needs node and a built packages/verify")
async def test_bundle_classes_detect_with_python_ts_parity(tmp_path, key, no_network):
    r, _ = make_runner(tmp_path, bundle_source="vectors", trials=2)
    rows: list = []
    for cid in ("A07", "A08", "A09", "A10"):
        await r.run_class(cls(key, cid), emit=rows.append)
    assert len(rows) == 8 and not r.not_run
    for row in rows:
        assert row["parity"] is True, row["parityDiffs"]
        assert row["detected"] is True, row
    assert r.bundle_info["source"] == "vectors"
    assert r.bundle_info["baseline"]["parity"] is True
    await r.aclose()


async def test_parity_mismatch_fails_the_trial(tmp_path, key, monkeypatch, no_network):
    r, _ = make_runner(tmp_path, bundle_source="vectors", trials=1)

    def fake_ts(node, cli, b, cfg, record, timeout_s=60.0):
        lad = R.py_ladder(b, r.ctx.verifier, record)
        if b is r.ctx.real_bundle:
            return lad  # baseline agrees
        return {**lad, "steps": {**lad["steps"], "block_hash": True}}

    monkeypatch.setattr(R, "ts_verify", fake_ts)
    rows: list = []
    await r.run_class(cls(key, "A07"), emit=rows.append)
    assert rows[0]["parity"] is False and rows[0]["detected"] is False
    assert rows[0]["observed"] == "PARITY_MISMATCH"
    await r.aclose()


# ---------------------------------------------------------------------------- live classes


@respx.mock
async def test_live_class_end_to_end_with_a_stubbed_injection(tmp_path, key, monkeypatch):
    r, clock = make_runner(tmp_path, trials=2)
    sent = []

    async def fake_a01(ctx):
        sent.append(ctx.live)
        return A.InjectionRecord("A01", BID, None, A.expected_for("A01"), clock(), {})

    monkeypatch.setattr(A, "a01_forged_signature", fake_a01)
    replies = iter([httpx.Response(404), httpx.Response(200, json={"verdict": "FORGED"}),
                    httpx.Response(200, json={"verdict": "PRODUCER_SIGNED"})] +
                   [httpx.Response(200, json={"verdict": "PRODUCER_SIGNED"})] * 30)
    respx.get(f"{API}/messages/{BID}").mock(side_effect=lambda q: next(replies))
    respx.get(f"{API}/alerts").mock(return_value=httpx.Response(200, json={"items": []}))
    rows: list = []
    await r.run_class(cls(key, "A01"), emit=rows.append)
    assert sent == [True, True]
    assert [x["detected"] for x in rows] == [True, False]
    assert rows[1]["observed"] == "PRODUCER_SIGNED"
    await r.aclose()


async def test_injection_errors_are_not_run_not_misses(tmp_path, key, monkeypatch):
    r, _ = make_runner(tmp_path, trials=2)

    async def broken(ctx):
        raise httpx.ConnectError("relay down")

    monkeypatch.setattr(A, "a20_chain_gap", broken)
    monkeypatch.setattr(r, "register_ies", _no_ies)
    rows: list = []
    await r.run_class(cls(key, "A20"), emit=rows.append)
    assert [x["status"] for x in rows] == ["error", "error"]
    card = R.write_scorecard(tmp_path / "o", key, rows, None, [], [], {}, {})
    assert card["attacks"] == 0
    assert card["not_run"] == [{"class": "A20", "trials": 2,
                                "reason": "injection failed: ConnectError: relay down"}]
    assert "(2 planned trials not run: A20)" in card["headline"]
    await r.aclose()


async def _no_ies(n):
    return [], []


async def test_missing_setup_is_reported(tmp_path, key):
    r, _ = make_runner(tmp_path)
    reasons = {c: r.missing_setup(cls(key, c)) for c in ("A05", "A11", "A16", "A18", "A19",
                                                         "A01")}
    assert "revoked" in reasons["A05"] and "search key" in reasons["A11"]
    assert "ingest token" in reasons["A16"] and "ingest token" in reasons["A18"]
    assert "DSN" in reasons["A19"] and reasons["A01"] is None
    rows: list = []
    await r.run_class(cls(key, "A05"), emit=rows.append)
    assert rows == [] and r.not_run[0]["class"] == "A05" and r.not_run[0]["trials"] == 20
    await r.aclose()


async def test_trial_hook_sets_orion_scores_for_registered_ies(tmp_path, monkeypatch):
    r, _ = make_runner(tmp_path)
    calls = []
    monkeypatch.setattr(r.orion, "set_score_sync", lambda ie, s: calls.append((ie, s)))
    r.registered = {"D:000000000001", "D:000000000002"}
    r.ctx.ie_pool, r.ctx.stale_pool = ["D:000000000001"], ["D:000000000002"]
    r.ctx.begin_trial()
    assert calls == [("D:000000000001", r.ctx.baseline_score), ("D:000000000002", 0.5)]
    r.ctx.begin_trial()  # pools empty: random ids, not registered, Orion untouched
    assert len(calls) == 2
    await r.aclose()


@respx.mock
async def test_exclusive_producer_check(tmp_path):
    r, clock = make_runner(tmp_path)
    iss = r.ctx.producer.iss
    route = respx.get(f"{API}/messages").mock(return_value=httpx.Response(200, json={"items": [
        {"blockId": BID, "dateMs": clock.ms - 30_000}]}))
    with pytest.raises(R.PreflightError, match="another producer"):
        await r.check_exclusive(iss)
    assert route.calls[0].request.url.params["iss"] == iss
    r.cfg.allow_concurrent_producer = True
    assert (await r.check_exclusive(iss))["recentProducerBlocks"] == 1
    route.mock(return_value=httpx.Response(200, json={"items": [
        {"blockId": BID, "dateMs": clock.ms - 600_000}]}))
    r.cfg.allow_concurrent_producer = False
    assert (await r.check_exclusive(iss))["recentProducerBlocks"] == 0
    await r.aclose()


# ---------------------------------------------------------------------------- trap


@respx.mock
async def test_collect_trap_scores_attributable_alerts_and_verdicts():
    sent = [T.Sent(0, "trust.score", "T:1", 10, 200, "0x" + "01" * 32, "PRODUCER_SIGNED"),
            T.Sent(1, "LLO-K8s", None, 20, 200, "0x" + "02" * 32, "RELAY_ATTESTED"),
            T.Sent(2, "LLO-K8s", None, 30, 403, None, None, "refused"),
            T.Sent(3, "self-orchestrator", "T:1", 40, 200, "0x" + "03" * 32,
                   "UNSIGNED_LEGACY")]
    verdicts = {"01": "PRODUCER_SIGNED", "02": "RELAY_ATTESTED", "03": None}
    for b, v in verdicts.items():
        body = {"verdict": v, "indexed": v is not None}
        respx.get(f"{API}/messages/0x{b * 32}").mock(return_value=httpx.Response(200, json=body))
    respx.get(f"{API}/alerts", params={"block_id": "0x" + "01" * 32}).mock(
        return_value=httpx.Response(200, json={"items": [
            alert(1, "CHAIN_GAP", "medium", 50), alert(2, "STALE", "low", 10_000)]}))
    for b in ("02", "03"):
        respx.get(f"{API}/alerts", params={"block_id": "0x" + b * 32}).mock(
            return_value=httpx.Response(200, json={"items": []}))
    respx.get(f"{API}/alerts", params={"ie": "T:1"}).mock(return_value=httpx.Response(
        200, json={"items": [alert(1, "CHAIN_GAP", "medium", 50)]}))
    respx.get(f"{API}/alerts").mock(return_value=httpx.Response(200, json={"items": [
        alert(1, "CHAIN_GAP", "medium", 50), alert(9, "SHADOW", "high", 60, block_id="0xff")]}))
    async with httpx.AsyncClient() as http:
        trap, rows = await R.collect_trap(R.ExplorerApi(API, http), sent, ["T:1"],
                                          start_ms=0, end_ms=60_000, window_end_ms=5_000)
    assert trap["messages"] == 3 and trap["failed_sends"] == 1
    assert trap["alerts"] == 1 and trap["alert_rules"] == {"CHAIN_GAP": 1}  # STALE after window
    assert trap["verdicts"] == {"PRODUCER_SIGNED": 1, "RELAY_ATTESTED": 1}
    assert trap["not_indexed"] == 1
    assert trap["all_alerts_in_window"] == {"CHAIN_GAP": 1, "SHADOW": 1}
    assert [x["n"] for x in rows] == [0, 1, 3]


# ---------------------------------------------------------------------------- results


def test_scorecard_files_and_rescore(tmp_path, key):
    out = tmp_path / "res"
    rows = [{"class": "A01", "trial": t, "status": "ok", "detected": t != 1,
             "observed": "FORGED" if t != 1 else None, "alerts": ["SHADOW"],
             "latency_ms": 3000 + t, "lateAlerts": ["FORGED"] if t == 0 else []}
            for t in range(3)]
    rows.append({"class": "A02", "trial": 0, "status": "error", "error": "boom",
                 "detected": False, "observed": None})
    controls = [{"control": "C01", "trial": 0, "status": "ok", "blockId": BID,
                 "indexed": True, "verdict": "PRODUCER_SIGNED", "alerts": []}]
    trap = {"messages": 40, "duration_s": 180, "alerts": 0, "verdicts": {"PRODUCER_SIGNED": 40}}
    meta = {"git": {"commit": "abc", "dirty": False}, "configHash": "f" * 64,
            "answerKeySha256": "e" * 64, "config": {"trials": 3}}
    card = R.write_scorecard(out, key, rows, trap, controls,
                             [{"class": "A05", "trials": 3, "reason": "no revoked identity"}],
                             meta, {"A01": {"FORGED": 1}})
    assert card["detected"] == 2 and card["attacks"] == 3
    assert card["controls"] == {"trials": 1, "passed": 1, "failures": []}
    assert card["valid"] is True
    assert card["headline"] == ("detected 2/3 attacks, 0/40 false positives "
                                "(4 planned trials not run: A02, A05)")
    assert card["run"]["git"]["commit"] == "abc" and card["run"]["trialsPerClass"] == 3
    md = (out / "scorecard.md").read_text(encoding="utf-8")
    assert "A01: FORGED x1" in md and "no revoked identity" in md and "Commit abc" in md
    (out / "trials.jsonl").write_text("\n".join(json.dumps(x) for x in [*rows, *controls]))
    (out / "run.json").write_text(json.dumps(meta))
    (out / "trap.json").write_text(json.dumps(trap))
    again = R.rescore(out)
    assert again["headline"] == card["headline"]
    assert again["late_alerts"] == {"A01": {"FORGED": 1}}


def test_config_hash_ignores_secrets_and_output(tmp_path):
    a = R.RunConfig(out="x", ingest_token="t1", db_dsn="postgresql://u:p@h/db")
    b = R.RunConfig(out="y", ingest_token="t2", db_dsn=None)
    assert R.config_hash(a, "key") == R.config_hash(b, "key")
    assert R.config_hash(a, "key") != R.config_hash(a, "key2")
    assert R.config_hash(a, "key") != R.config_hash(R.RunConfig(seed=2), "key")
    pub = a.public()
    assert pub["ingest_token"] == "<set>" and pub["db_dsn"] == "<set>"
    assert "t1" not in json.dumps(pub) and "u:p" not in json.dumps(pub)


def test_outsider_is_a_did_key_the_indexer_resolves():
    from witness_indexer.resolver import did_key_public

    ident = R.did_key_identity(R.seeded_key(1, "outsider"))
    assert did_key_public(ident.iss) == ident.key.public_key().public_bytes_raw()
    assert ident.kid.split("#", 1)[0] == ident.iss
    assert R.did_key_identity(R.seeded_key(1, "outsider")).iss == ident.iss  # seeded
    assert R.seeded_key(2, "outsider").public_key().public_bytes_raw() != \
        ident.key.public_key().public_bytes_raw()


def test_cli_reads_env_files_and_masks_secrets(tmp_path):
    env = tmp_path / "api.env"
    env.write_text("# comment\nWITNESS_INGEST_TOKEN='tok-1234567890abcdef'\nOTHER=1\n")
    a = R._parser().parse_args(["run", "--env-file", str(env), "--trials", "2",
                                "--classes", "A01,A17", "--no-trap"])
    cfg = R.config_from_args(a, environ={"WITNESS_CHAOS_MQTT": "mqtt://u:p@127.0.0.1:1883"})
    assert cfg.ingest_token == "tok-1234567890abcdef" and cfg.ingest_via == "both"
    assert cfg.classes == ["A01", "A17"] and cfg.trials == 2 and cfg.trap is False
    t = R._parser().parse_args(["trap", "--trap-minutes", "3"])
    tcfg = R.config_from_args(t, environ={})
    assert tcfg.classes == [] and tcfg.controls is False and tcfg.trap is True
    assert tcfg.ingest_via == "http" and tcfg.trap_minutes == 3


def test_read_search_key_matches_the_relay_format(tmp_path):
    raw = bytes(range(32))
    p = tmp_path / "search.key"
    p.write_text(base64.urlsafe_b64encode(raw).rstrip(b"=").decode() + "\n")
    assert R.read_search_key(str(p)) == raw
    p.write_text("AAAA")
    with pytest.raises(ValueError):
        R.read_search_key(str(p))


def test_mqtt_route_publishes_the_relay_record_shape(key):
    ctx = A.AttackContext(live=True, ingest_via="mqtt")
    got = []

    async def pub(topic, payload):
        got.append((topic, json.loads(payload)))

    ctx.mqtt_publish = pub
    record = A.submission_record("trust.score", {"a": 1}, b"{}", "0x" + "11" * 32, now_ms=5)
    import asyncio

    assert asyncio.run(A._post_ingest(ctx, record)) == ["mqtt"]
    assert got == [("aerios/iota/submissions/trust.score", record)]
    assert A.submission_topic("a+b#c") == "aerios/iota/submissions/a_b_c"


def test_mqtt_url_from_relay_env_with_host_override(tmp_path):
    env = tmp_path / "relay.env"
    env.write_text("RELAY_MQTT_URL=mqtt://relay:s3cr%40t@witness-mosquitto:1883\n")
    a = R._parser().parse_args(["run", "--env-file", str(env), "--mqtt-host", "127.0.0.1"])
    cfg = R.config_from_args(a, environ={})
    assert cfg.mqtt_url == "mqtt://relay:s3cr%40t@127.0.0.1:1883"
    assert cfg.ingest_via == "mqtt"
    assert R.with_host("mqtt://h:1883", "x:2000") == "mqtt://x:2000"


@respx.mock
async def test_both_ingest_routes_survive_one_failing():
    route = respx.post(f"{API}/ingest").mock(return_value=httpx.Response(202, json={}))

    async def down(topic, payload):
        raise OSError("broker refused")

    ctx = A.AttackContext(live=True, ingest_via="both", ingest_url=f"{API}/ingest",
                          ingest_token="t" * 20, mqtt_publish=down)
    async with httpx.AsyncClient() as http:
        ctx.http = http
        rec = A.submission_record("trust.score", {}, b"{}", None, now_ms=1)
        used = await A._post_ingest(ctx, rec)
        assert used[0].startswith("mqtt-failed: OSError") and used[1] == "http"
        assert route.calls[0].request.headers["authorization"] == "Bearer " + "t" * 20
        route.mock(return_value=httpx.Response(401))
        with pytest.raises(OSError):
            await A._post_ingest(ctx, rec)


# ---------------------------------------------------------------------------- run identity


def test_keys_make_a_run_only_producer_and_eval_policy(tmp_path):
    base = json.loads((REPO / "chaos" / "demo-policy.json").read_text(encoding="utf-8"))
    made = R.write_keys(str(tmp_path / "chaos"), str(REPO / "chaos" / "demo-policy.json"))
    ident = R.identity_from_file(made["key"])
    assert ident.iss == made["producer"] and ident.iss.startswith("did:key:z")
    assert ident.iss not in R.live_dids(str(REPO))
    pol = json.loads(Path(made["policy"]).read_text(encoding="utf-8"))
    assert pol["tags"]["trust.score"]["allowed"] == [
        *base["tags"]["trust.score"]["allowed"], ident.iss]
    pol["tags"]["trust.score"]["allowed"] = base["tags"]["trust.score"]["allowed"]
    assert pol == base  # nothing else changes
    with pytest.raises(FileExistsError):
        R.write_keys(str(tmp_path / "chaos"), str(REPO / "chaos" / "demo-policy.json"))
    again = R.write_keys(str(tmp_path / "chaos"), str(REPO / "chaos" / "demo-policy.json"),
                         force=True)
    assert again["producer"] != made["producer"]


def test_live_dids_include_the_trust_manager():
    ids = json.loads((REPO / "deploy" / "identity" / "testnet.json").read_text())
    tm = next(i["did"] for i in ids["identities"] if i["name"] == "trust-manager")
    assert tm in R.live_dids(str(REPO))


@respx.mock
async def test_identity_check_refuses_live_dids_and_unlisted_producers(tmp_path):
    r, _ = make_runner(tmp_path)
    iss = r.ctx.producer.iss
    ids = json.loads((REPO / "deploy" / "identity" / "testnet.json").read_text())
    tm = next(i["did"] for i in ids["identities"] if i["name"] == "trust-manager")

    def identity(allowed, anchor_dids=()):
        return httpx.Response(200, json={
            "anchor": {"status": "ok", "identities": [{"did": d} for d in anchor_dids]},
            "policy": {"hash": "0x01", "tags": {"trust.score": {"allowed": allowed}}}})

    route = respx.get(f"{API}/identity").mock(return_value=identity([tm]))
    with pytest.raises(R.PreflightError, match="does not allow"):
        await r.check_identity(iss)
    route.mock(return_value=identity([tm, iss]))
    assert (await r.check_identity(iss))["trustScoreWriters"] == [tm, iss]
    with pytest.raises(R.PreflightError, match="live component"):
        await r.check_identity(tm)
    route.mock(return_value=identity([iss], anchor_dids=[iss]))
    with pytest.raises(R.PreflightError, match="live component"):
        await r.check_identity(iss)
    await r.aclose()


async def test_a19_only_picks_rows_of_the_run_producer(monkeypatch):
    import sys
    import types

    seen = []

    class Cur:
        async def fetchone(self):
            return (bytes.fromhex("cd" * 32),)

    class Conn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def execute(self, sql, params):
            seen.append((sql, params))
            return Cur()

    class AsyncConnection:
        @staticmethod
        async def connect(dsn, autocommit):
            return Conn()

    monkeypatch.setitem(sys.modules, "psycopg", types.SimpleNamespace(
        AsyncConnection=AsyncConnection))
    prod = A.Identity("did:key:zRun", "did:key:zRun#zRun", Ed25519PrivateKey.generate())
    ctx = A.AttackContext(live=True, db_dsn="postgresql://x", producer=prod,
                          tampered=[bytes.fromhex("ab" * 32)])
    rec = await A.a19_db_tamper(ctx)
    assert seen[0] == (A.VICTIM_SQL, ("trust.score", "did:key:zRun",
                                      [bytes.fromhex("ab" * 32)]))
    assert seen[1] == (A.TAMPER_SQL, (bytes.fromhex("cd" * 32),))
    assert ctx.tampered[-1] == bytes.fromhex("cd" * 32)
    assert rec.block_id == "0x" + "cd" * 32 and rec.detail["victimIss"] == "did:key:zRun"


# ---------------------------------------------------------------------------- control gate


async def test_control_that_cannot_run_fails_the_run(tmp_path, key, monkeypatch):
    r, _ = make_runner(tmp_path, trials=2)

    async def broken(ctx):
        raise httpx.ConnectError("relay down")

    monkeypatch.setitem(A.CONTROLS, "C01", broken)
    monkeypatch.setattr(r, "register_ies", _no_ies)
    rows: list = []
    await r.run_class(key["controls"][0], control=True, emit=rows.append)
    assert [(x["control"], x["status"], x["passed"]) for x in rows] == [
        ("C01", "error", False)] * 2
    card = R.write_scorecard(tmp_path / "o", key, [], None, rows, [], {}, {})
    assert card["valid"] is False and card["controls"]["passed"] == 0
    assert card["headline"].startswith("INVALID RUN (control C01 failed)")
    await r.aclose()


@respx.mock
async def test_control_row_records_indexing_and_verdict(tmp_path, key, monkeypatch):
    r, clock = make_runner(tmp_path, trials=1)

    async def c01(ctx):
        return A.InjectionRecord("C01", BID, None, A.expected_for("C01"), clock(), {})

    monkeypatch.setitem(A.CONTROLS, "C01", c01)
    monkeypatch.setattr(r, "register_ies", _no_ies)
    respx.get(f"{API}/messages/{BID}").mock(return_value=httpx.Response(
        200, json={"verdict": "PRODUCER_SIGNED", "indexed": False}))
    respx.get(f"{API}/alerts").mock(return_value=httpx.Response(200, json={"items": []}))
    rows: list = []
    await r.run_class(key["controls"][0], control=True, emit=rows.append)
    assert rows[0]["indexed"] is False and rows[0]["passed"] is False
    assert rows[0]["why"] == "block never indexed"
    await r.aclose()


@pytest.mark.parametrize(("valid", "code"), [(True, 0), (False, 1)])
def test_invalid_run_exits_non_zero(monkeypatch, valid, code):
    async def fake(cfg):
        return {"valid": valid, "headline": "h"}

    monkeypatch.setattr(R, "amain", fake)
    assert R.main(["run", "--no-trap"]) == code


# ---------------------------------------------------------------------------- local only


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "LOCALHOST", "[::1]",
                                  "127.10.0.3"])
def test_loopback_hosts_are_accepted(host):
    cfg = R.RunConfig(api=f"http://{host}:7200", relay=f"http://{host}:5557",
                      hornet=f"http://{host}:14265", orion=f"http://{host}:1026",
                      anchor=f"http://{host}:7300", mqtt_url=f"mqtt://u:p@{host}:1883",
                      db_dsn=f"postgresql://u:p@{host}:5432/postgres")
    assert R.check_local(cfg) == {"nonlocal": [], "allowNonlocal": False}


@pytest.mark.parametrize(("field", "value", "flag"), [
    ("api", "http://10.0.0.5:7200", "--api 10.0.0.5"),
    ("relay", "http://witness-relay:5555", "--relay witness-relay"),
    ("hornet", "http://0.0.0.0:14265", "--hornet 0.0.0.0"),
    ("orion", "http://orion.example.org:1026", "--orion orion.example.org"),
    ("anchor", "http://192.168.1.2:7300", "--anchor 192.168.1.2"),
    ("mqtt_url", "mqtt://relay:s3cret@broker.lan:1883", "--mqtt broker.lan"),
    ("db_dsn", "postgresql://postgres:pw@db.example:5432/postgres", "--db-dsn db.example"),
    ("db_dsn", "host=127.0.0.1,10.1.1.1 dbname=x", "--db-dsn 10.1.1.1"),
])
def test_nonlocal_endpoints_are_refused(field, value, flag):
    cfg = R.RunConfig(**{field: value})
    with pytest.raises(R.PreflightError) as err:
        R.check_local(cfg)
    assert flag in str(err.value)
    assert "s3cret" not in str(err.value) and "pw@" not in str(err.value)
    cfg.allow_nonlocal = True
    assert R.check_local(cfg) == {"nonlocal": [flag], "allowNonlocal": True}


def test_dsn_without_host_or_with_a_socket_is_local():
    assert R.check_local(R.RunConfig(db_dsn="dbname=postgres user=postgres"))["nonlocal"] == []
    assert R.check_local(R.RunConfig(db_dsn="host=/var/run/postgresql dbname=x"))[
        "nonlocal"] == []


async def test_run_refuses_a_remote_stack_before_sending_anything(tmp_path, no_network):
    cfg = R.RunConfig(api="http://203.0.113.9:7200", out=str(tmp_path / "o"), trap=False)
    r = R.Runner(cfg, http=httpx.AsyncClient())
    with pytest.raises(R.PreflightError, match="--api 203.0.113.9"):
        await r.run()
    assert not (tmp_path / "o").exists()
    await r.aclose()


def test_allow_nonlocal_is_a_recorded_flag():
    a = R._parser().parse_args(["run", "--allow-nonlocal"])
    cfg = R.config_from_args(a, environ={})
    assert cfg.allow_nonlocal is True and cfg.public()["allow_nonlocal"] is True


@respx.mock
async def test_alerts_older_than_the_injection_are_not_the_trials(key):
    clock = Clock()
    respx.get(f"{API}/messages/{BID}").mock(return_value=httpx.Response(
        200, json={"verdict": "PRODUCER_SIGNED", "indexed": True}))
    respx.get(f"{API}/alerts").mock(return_value=httpx.Response(200, json={"items": [
        alert(1, "UNSIGNED", "medium", clock.ms - 60_000),
        alert(2, "DB_TAMPER", "critical", clock.ms + 9_000)]}))
    r = rec("A19", at=clock.ms)
    o = await run_observe(key, "A19", r, clock, by_ie=False)
    assert o.detected and list(o.alerts) == [2]
    row = R.trial_row(cls(key, "A19"), 0, r, o, trial_start_ms=r.injected_at_ms)
    assert row["alerts"] == ["DB_TAMPER"] and row["latency_ms"] == 9_000
