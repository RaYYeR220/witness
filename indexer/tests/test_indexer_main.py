import asyncio
import json
import logging
import os
import uuid

import psycopg
import pytest
from fakechain import FakeChain, FakeSource
from witness_core import policy
from witness_indexer import main as cli
from witness_indexer.source_inx import InxSource
from witness_indexer.source_rest import RestSource
from witness_indexer.store import Store


def test_parse_args_defaults(monkeypatch):
    monkeypatch.setenv("WITNESS_DB", "postgresql://u@h/db")
    a = cli.parse_args([])
    assert (a.source, a.inx, a.rest, a.db, a.schema) == (
        "inx", "127.0.0.1:9029", "http://127.0.0.1:14265", "postgresql://u@h/db", "witness")
    assert (a.policy, a.mqtt, a.validate) == (None, None, False)


def test_parse_args_requires_a_database(monkeypatch):
    monkeypatch.delenv("WITNESS_DB", raising=False)
    with pytest.raises(SystemExit):
        cli.parse_args([])


def test_parse_args_full():
    a = cli.parse_args(["--source", "rest", "--db", "postgresql://x", "--schema", "s",
                        "--policy", "p.json", "--mqtt", "mqtt://127.0.0.1:1883", "--validate"])
    assert (a.source, a.schema, a.policy, a.mqtt, a.validate) == (
        "rest", "s", "p.json", "mqtt://127.0.0.1:1883", True)


def test_load_policy(tmp_path, caplog):
    p = tmp_path / "policy.json"
    p.write_text(json.dumps({"version": 3, "tags": {"trust.score": {"allowed": ["did:a"]}}}))
    pol = cli.load_policy(str(p))
    assert pol.version == 3 and policy.allowed(pol, "trust.score", "did:a")
    assert not policy.allowed(pol, "trust.score", "did:b")
    with caplog.at_level(logging.WARNING):
        open_pol = cli.load_policy(None)
    assert policy.allowed(open_pol, "anything", "did:anyone")
    assert "no writer policy" in caplog.text


async def test_open_source_falls_back_to_rest(caplog):
    args = cli.parse_args(["--db", "postgresql://x", "--inx", "127.0.0.1:1",
                           "--inx-timeout", "0.3", "--rest", "http://hornet.test"])
    with caplog.at_level(logging.WARNING, logger="witness_indexer.main"):
        src = await cli.open_source(args)
    try:
        assert isinstance(src, RestSource) and src.base_url == "http://hornet.test"
        assert "falling back to REST" in caplog.text
    finally:
        await src.close()


async def test_open_source_rest_when_asked():
    args = cli.parse_args(["--db", "postgresql://x", "--source", "rest"])
    src = await cli.open_source(args)
    assert isinstance(src, RestSource)
    await src.close()


async def test_open_source_inx_when_reachable(monkeypatch):
    async def ok(self):
        self._stub = object()

    monkeypatch.setattr(InxSource, "connect", ok)
    monkeypatch.setattr(InxSource, "close", lambda self: _noop())
    src = await cli.open_source(cli.parse_args(["--db", "postgresql://x"]))
    assert isinstance(src, InxSource) and src.addr == "127.0.0.1:9029"


async def _noop():
    return None


@pytest.mark.skipif(not os.environ.get("WITNESS_TEST_PG"), reason="WITNESS_TEST_PG is unset")
async def test_amain_indexes_and_shuts_down_cleanly(monkeypatch):
    chain = FakeChain()
    for _ in range(3):
        chain.add([("trust.score", b'{"id":"D:aabbccddeeff","score":0.5}')])
    src = FakeSource(chain, tail=True)

    async def fake_open_source(args):
        return src

    monkeypatch.setattr(cli, "open_source", fake_open_source)
    schema = f"t_{uuid.uuid4().hex[:12]}"
    args = cli.parse_args(["--db", os.environ["WITNESS_TEST_PG"], "--schema", schema])
    store = await Store.open(os.environ["WITNESS_TEST_PG"], schema=schema)
    stop = asyncio.Event()
    task = asyncio.create_task(cli.amain(args, stop=stop))
    try:
        async def indexed() -> None:
            while True:
                try:
                    if await store.get_cursor() == 3:
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
        assert (await store.stats())["messages"] == 3
    finally:
        stop.set()
        await asyncio.gather(task, return_exceptions=True)
        await store.drop_schema()
        await store.close()


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
