"""Against the running aeriOS IOTA stack (WITNESS_LIVE=1): HORNET REST :14265, INX :9029."""

import asyncio
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from witness_core import merkle
from witness_indexer.pipeline import Indexer
from witness_indexer.source_inx import InxSource
from witness_indexer.source_rest import RestSource
from witness_indexer.store import Store

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("WITNESS_LIVE") != "1", reason="set WITNESS_LIVE=1"),
]

INX = os.environ.get("WITNESS_INX", "127.0.0.1:9029")
HORNET = os.environ.get("WITNESS_HORNET", "http://127.0.0.1:14265")
# How the node's container reaches this machine (Docker Desktop name by default).
ROUTE_HOST = os.environ.get("WITNESS_ROUTE_HOST", "host.docker.internal")
ROUTE = "witness-livetest/v1"  # never the real API's route, which may be registered


async def take(aiter, n: int) -> list:
    out = []
    async for item in aiter:
        out.append(item)
        if len(out) == n:
            break
    await aiter.aclose()
    return out


async def recent_start(src: InxSource, back: int = 2) -> int:
    status = await src.node_status()
    return max(1, status.confirmed_milestone.milestone_info.milestone_index - back)


async def test_inx_live_streams_milestones_and_cones():
    async with InxSource(INX) as src:
        start = await recent_start(src)
        got = await take(src.milestones(start), 3)
        assert [m.index for m in got] == [start, start + 1, start + 2]
        assert got[1].prev_id == got[0].id and got[2].prev_id == got[1].id
        for m in got:
            cone = [b async for b in src.cone(m.index)]
            assert merkle.root([b.block_id for b in cone]) == m.inclusion_root


async def test_rest_source_matches_inx_live():
    async with InxSource(INX) as inx, RestSource(HORNET) as rest:
        start = await recent_start(inx, back=3)
        via_inx = await take(inx.milestones(start), 2)
        via_rest = await take(rest.milestones(start), 2)
        assert via_rest == via_inx
        for m in via_inx:
            assert [b async for b in rest.cone(m.index)] == [b async for b in inx.cone(m.index)]


class _Health(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"status": "ok", "path": self.path}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


async def test_inx_live_register_route_proxies():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Health)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"{HORNET}/api/{ROUTE}/healthz"
    try:
        async with InxSource(INX) as src, httpx.AsyncClient(timeout=5) as http:
            await src.register_route(ROUTE, ROUTE_HOST, server.server_address[1])
            try:
                r = await http.get(url)
                assert r.status_code == 200
                assert r.json() == {"status": "ok", "path": "/healthz"}
            finally:
                await src.unregister_route(ROUTE)
            assert (await http.get(url)).status_code == 404
    finally:
        server.shutdown()


async def test_index_live_node(store: Store):
    """Index real milestones into a throwaway schema, including a block written straight to
    the node (no Messages API involved)."""
    tag = f"witness.livetest.{int(time.time())}"
    async with httpx.AsyncClient(base_url=HORNET, timeout=10) as http:
        r = await http.post("/api/core/v2/blocks", json={
            "protocolVersion": 2,
            "payload": {"type": 5, "tag": "0x" + tag.encode().hex(),
                        "data": "0x" + b'{"probe": true}'.hex()}})
        r.raise_for_status()
        shadow = bytes.fromhex(r.json()["blockId"][2:])

    src = InxSource(INX)
    start = await recent_start(src, back=3)
    await store.set_cursor(start - 1)
    ix = Indexer(src, store)
    task = asyncio.create_task(ix.run())
    try:
        async def until_indexed() -> None:
            while await store.get_message(shadow) is None:
                await asyncio.sleep(0.25)

        await asyncio.wait_for(until_indexed(), 60)
    finally:
        await ix.stop()
        await task
        await src.close()

    row = await store.get_message(shadow)
    assert row["tag"] == tag and row["json"] == {"probe": True}
    assert row["verdict"] == "UNSIGNED_LEGACY" and row["status"] is None
    assert await store.lifecycle(shadow) == []
    cursor = await store.get_cursor()
    assert cursor >= row["ms_index"] >= start
    for i in range(start, cursor + 1):
        ms = await store.milestone(i)
        assert ms is not None, f"milestone {i} missing"
        assert merkle.root(await store.cone_ids(i)) == ms["inclusion_root"]
