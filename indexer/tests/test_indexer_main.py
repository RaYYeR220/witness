import asyncio
import json
import logging
import os
import uuid

import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fakechain import FakeChain, FakeSource, signed, tamper
from witness_core import policy
from witness_indexer import main as cli
from witness_indexer.incidents import CorrelatedRules, IncidentEngine, MqttAlertPublisher
from witness_indexer.pipeline import ALLOW_ALL
from witness_indexer.resolver import DidResolver
from witness_indexer.rules import RulesEngine
from witness_indexer.source_inx import InxSource
from witness_indexer.source_rest import RestSource
from witness_indexer.store import Store

ALICE = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)


def test_parse_args_defaults(monkeypatch):
    monkeypatch.setenv("WITNESS_DB", "postgresql://u@h/db")
    monkeypatch.delenv("WITNESS_MQTT", raising=False)
    a = cli.parse_args(["--policy", "p.json"])
    assert (a.source, a.inx, a.rest, a.db, a.schema) == (
        "inx", "127.0.0.1:9029", "http://127.0.0.1:14265", "postgresql://u@h/db", "witness")
    assert (a.policy, a.allow_any_writer, a.mqtt, a.validate) == ("p.json", False, None, False)


@pytest.mark.parametrize("policy_args", [[], ["--policy", "p.json", "--allow-any-writer"]])
def test_parse_args_requires_exactly_one_policy_choice(policy_args):
    with pytest.raises(SystemExit):
        cli.parse_args(["--db", "postgresql://x", *policy_args])


def test_parse_args_requires_a_database(monkeypatch):
    monkeypatch.delenv("WITNESS_DB", raising=False)
    with pytest.raises(SystemExit):
        cli.parse_args(["--allow-any-writer"])


def test_parse_args_full():
    a = cli.parse_args(["--source", "rest", "--db", "postgresql://x", "--schema", "s",
                        "--policy", "p.json", "--mqtt", "mqtt://127.0.0.1:1883", "--validate"])
    assert (a.source, a.schema, a.policy, a.mqtt, a.validate) == (
        "rest", "s", "p.json", "mqtt://127.0.0.1:1883", True)


def test_parse_args_broker_from_environment(monkeypatch):
    # Containers pass the broker (with its credentials) in the environment, not on argv.
    monkeypatch.setenv("WITNESS_MQTT", "mqtt://indexer:pw@broker:1883")
    a = cli.parse_args(["--db", "postgresql://x", "--allow-any-writer"])
    assert a.mqtt == "mqtt://indexer:pw@broker:1883"
    a = cli.parse_args(["--db", "postgresql://x", "--allow-any-writer", "--mqtt", "mqtt://h:1"])
    assert a.mqtt == "mqtt://h:1"
    monkeypatch.setenv("WITNESS_MQTT", "")
    assert cli.parse_args(["--db", "postgresql://x", "--allow-any-writer"]).mqtt is None


def test_writer_policy(tmp_path, caplog):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({"version": 3, "tags": {"trust.score": {"allowed": ["did:a"]}}}))
    pol, mode = cli.writer_policy(cli.parse_args(["--db", "postgresql://x", "--policy", str(p)]))
    assert (pol.version, mode) == (3, "file")
    assert policy.allowed(pol, "trust.score", "did:a")
    assert not policy.allowed(pol, "trust.score", "did:b")
    with caplog.at_level(logging.WARNING):
        open_pol, mode = cli.writer_policy(
            cli.parse_args(["--db", "postgresql://x", "--allow-any-writer"]))
    assert mode == "allow-any" and policy.allowed(open_pol, "anything", "did:anyone")
    assert "ANY signer" in caplog.text


async def test_open_source_falls_back_to_rest(caplog):
    args = cli.parse_args(["--db", "postgresql://x", "--allow-any-writer", "--inx", "127.0.0.1:1",
                           "--inx-timeout", "0.3", "--rest", "http://hornet.test"])
    with caplog.at_level(logging.WARNING, logger="witness_indexer.main"):
        src = await cli.open_source(args)
    try:
        assert isinstance(src, RestSource) and src.base_url == "http://hornet.test"
        assert "falling back to REST" in caplog.text
    finally:
        await src.close()


async def test_open_source_rest_when_asked():
    args = cli.parse_args(["--db", "postgresql://x", "--allow-any-writer", "--source", "rest"])
    src = await cli.open_source(args)
    assert isinstance(src, RestSource)
    await src.close()


async def test_open_source_inx_when_reachable(monkeypatch):
    async def ok(self):
        self._stub = object()

    monkeypatch.setattr(InxSource, "connect", ok)
    monkeypatch.setattr(InxSource, "close", lambda self: _noop())
    src = await cli.open_source(cli.parse_args(["--db", "postgresql://x", "--allow-any-writer"]))
    assert isinstance(src, InxSource) and src.addr == "127.0.0.1:9029"


async def _noop():
    return None


@pytest.mark.skipif(not os.environ.get("WITNESS_TEST_PG"), reason="WITNESS_TEST_PG is unset")
async def test_amain_indexes_and_shuts_down_cleanly(monkeypatch):
    chain = FakeChain()
    for _ in range(2):
        chain.add([("trust.score", b'{"id":"D:aabbccddeeff","score":0.5}')])
    forged = tamper(signed(ALICE, "trust.score", {"id": "D:aabbccddeeff", "score": 0.9}, 1),
                    score=0.1)
    chain.add([("trust.score", forged)])
    src = FakeSource(chain, tail=True)

    async def fake_open_source(args):
        return src

    monkeypatch.setattr(cli, "open_source", fake_open_source)
    schema = f"t_{uuid.uuid4().hex[:12]}"
    args = cli.parse_args(["--db", os.environ["WITNESS_TEST_PG"], "--schema", schema,
                           "--allow-any-writer", "--resolver", "", "--orion", "",
                           "--rescan-s", "0.05"])
    store = await Store.open(os.environ["WITNESS_TEST_PG"], schema=schema)
    stop = asyncio.Event()
    task = asyncio.create_task(cli.amain(args, stop=stop))
    try:
        async def indexed() -> None:
            while True:
                try:
                    st = await store.stats()
                    if (st["cursor"] == 3 and st.get("rules") == "ok"
                            and st.get("incident-engine") == "ok"):
                        return
                except psycopg.errors.UndefinedTable:
                    pass  # amain has not migrated yet
                if task.done():
                    task.result()  # surface a crash instead of waiting for the timeout
                await asyncio.sleep(0.05)

        await asyncio.wait_for(indexed(), 10)
        stop.set()
        assert await asyncio.wait_for(task, 10) == 0
        assert src.closed
        stats = await store.stats()
        assert (stats["messages"], stats["policy"], stats["indexer"]) == (3, "allow-any", "ok")
        # the rules engine judged the stored messages and ran its periodic pass
        assert [a["rule"] for a in await store.alerts()] == ["FORGED"]
        assert stats["shadow"] == "no-baseline"
        # ... and the incident engine ran; with no Orion to vouch for the IE the forgery
        # names, it stays an alert
        assert await store.incidents() == []
        assert stats["alerts-mqtt"] == "disabled"  # no broker configured
    finally:
        stop.set()
        await asyncio.gather(task, return_exceptions=True)
        await store.drop_schema()
        await store.close()


def test_build_rules_wiring(caplog):
    args = cli.parse_args(["--db", "postgresql://x", "--allow-any-writer",
                           "--resolver", "http://anchor.test:7300/", "--orion", "http://orion.test"])
    store = object()
    rules, resolver, orion = cli.build_rules(args, store, ALLOW_ALL)
    assert isinstance(rules, RulesEngine) and isinstance(resolver, DidResolver)
    assert (rules.store, rules.resolver, rules.orion, rules.policy) == (
        store, resolver, orion, ALLOW_ALL)
    assert resolver.base_url == "http://anchor.test:7300"
    assert orion.base_url == "http://orion.test"
    assert rules.anchor is not None  # R11 reads checkpoints from the same anchor service
    assert rules.cfg.stale_after_s == 120  # R8: twice the Trust Manager's 1-minute cadence
    rules, _, _ = cli.build_rules(cli.parse_args(
        ["--db", "postgresql://x", "--allow-any-writer", "--stale-after-s", "900"]),
        store, ALLOW_ALL)
    assert rules.cfg.stale_after_s == 900
    with pytest.raises(SystemExit):
        cli.parse_args(["--db", "postgresql://x", "--allow-any-writer", "--stale-after-s", "0"])

    with caplog.at_level(logging.WARNING):
        rules, resolver, orion = cli.build_rules(
            cli.parse_args(["--db", "postgresql://x", "--allow-any-writer", "--resolver", "",
                            "--orion", ""]), store, ALLOW_ALL)
    assert resolver.base_url is None and orion is None and rules.orion is None
    assert "no --resolver" in caplog.text


def test_incident_engine_wiring(monkeypatch):
    monkeypatch.delenv("WITNESS_ALERTS_MQTT", raising=False)
    base = ["--db", "postgresql://x", "--allow-any-writer", "--schema", "s1"]
    a = cli.parse_args(base)
    assert (a.incidents, a.alerts_mqtt, a.incident_window_s, a.incident_quiet_s,
            a.incident_drop) == (True, None, 600.0, 1800.0, 0.2)
    store, orion = object(), object()
    eng = cli.build_incidents(a, store, orion, ALLOW_ALL)
    assert eng.policy is ALLOW_ALL
    assert isinstance(eng, IncidentEngine) and eng.publisher is None and eng.orion is orion
    assert (eng.cfg.window_ms, eng.cfg.quiet_close_ms, eng.cfg.drop_threshold) == (
        600_000, 1_800_000, 0.2)
    # alerts go to the submission broker unless told otherwise
    eng = cli.build_incidents(cli.parse_args([*base, "--mqtt", "mqtt://broker:1883",
                                              "--incident-window-s", "60",
                                              "--incident-drop", "0.3"]),
                              store, None, ALLOW_ALL)
    assert isinstance(eng.publisher, MqttAlertPublisher)
    assert eng.publisher._params["hostname"] == "broker"
    assert eng.publisher._params["identifier"] == "witness-indexer-alerts-s1"
    assert (eng.cfg.window_ms, eng.cfg.drop_threshold) == (60_000, 0.3)
    eng = cli.build_incidents(cli.parse_args([*base, "--mqtt", "mqtt://broker:1883",
                                              "--alerts-mqtt", ""]), store, None, ALLOW_ALL)
    assert eng.publisher is None
    monkeypatch.setenv("WITNESS_ALERTS_MQTT", "mqtt://alerts:1884")
    eng = cli.build_incidents(cli.parse_args(base), store, None, ALLOW_ALL)
    assert (eng.publisher._params["hostname"], eng.publisher._params["port"]) == (
        "alerts", 1884)
    off = cli.parse_args([*base, "--no-incidents"])
    assert cli.build_incidents(off, store, None, ALLOW_ALL) is None
    rules = object()
    assert CorrelatedRules(rules, eng).rules is rules


def test_parse_args_reverify_defaults():
    a = cli.parse_args(["--db", "postgresql://x", "--allow-any-writer", "--validate"])
    assert a.reverify_every_s == 60.0
    a = cli.parse_args(["--db", "postgresql://x", "--allow-any-writer", "--validate",
                        "--reverify-every-s", "0"])
    assert a.reverify_every_s == 0.0


@pytest.mark.skipif(not os.environ.get("WITNESS_TEST_PG"), reason="WITNESS_TEST_PG is unset")
@pytest.mark.parametrize(("every", "expected"), [
    ("0.05", "retrying (node unavailable)"),  # scheduled; the node below is not there
    ("0", "disabled"),
])
async def test_amain_schedules_reverification(monkeypatch, every, expected):
    chain = FakeChain()
    chain.add([("trust.score", b'{"id":"D:aabbccddeeff","score":0.5}')])
    src = FakeSource(chain, tail=True)

    async def fake_open_source(args):
        return src

    monkeypatch.setattr(cli, "open_source", fake_open_source)
    schema = f"t_{uuid.uuid4().hex[:12]}"
    # Port 9 (discard): nothing answers, so a pass stops at its first block.
    args = cli.parse_args(["--db", os.environ["WITNESS_TEST_PG"], "--schema", schema,
                           "--allow-any-writer", "--resolver", "", "--orion", "",
                           "--rest", "http://127.0.0.1:9", "--validate",
                           "--reverify-every-s", every])
    store = await Store.open(os.environ["WITNESS_TEST_PG"], schema=schema)
    stop = asyncio.Event()
    task = asyncio.create_task(cli.amain(args, stop=stop))
    try:
        async def reported() -> None:
            while True:
                try:
                    st = await store.stats()
                    if st["cursor"] == 1 and st.get("reverify") == expected:
                        return
                except psycopg.errors.UndefinedTable:
                    pass
                if task.done():
                    task.result()
                await asyncio.sleep(0.05)

        await asyncio.wait_for(reported(), 15)
        stop.set()
        assert await asyncio.wait_for(task, 15) == 0
    finally:
        stop.set()
        await asyncio.gather(task, return_exceptions=True)
        await store.drop_schema()
        await store.close()


def test_parse_args_rules_defaults():
    a = cli.parse_args(["--db", "postgresql://x", "--allow-any-writer"])
    assert (a.resolver, a.orion, a.periodic_s, a.rescan_s, a.rescan_batch) == (
        "http://127.0.0.1:7300", "http://127.0.0.1:1026", 30.0, 300.0, 200)


async def test_supervise_stops_the_rest_when_one_service_dies():
    stopped = []

    async def crash():
        await asyncio.sleep(0.01)
        raise RuntimeError("broker gone for good")

    async def forever():
        await asyncio.Event().wait()

    async def halt_b():
        stopped.append("b")

    async def halt_a():
        stopped.append("a")

    code = await cli._supervise([("a", crash, halt_a), ("b", forever, halt_b)], asyncio.Event())
    assert code == 1 and stopped == ["b"]


async def test_supervise_clean_stop():
    stop = asyncio.Event()
    stopped = []

    async def forever():
        await asyncio.Event().wait()

    async def halt():
        stopped.append(True)

    stop.set()
    assert await cli._supervise([("x", forever, halt)], stop) == 0
    assert stopped == [True]
