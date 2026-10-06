"""Against the running local stack (WITNESS_LIVE=1): the API served by uvicorn on a throwaway
schema, then reached directly and, when INX answers, through the node at /api/witness/v1."""

import asyncio
import json
import os
import socket
import uuid
from pathlib import Path

import httpx
import pytest
import uvicorn
from witness_api.app import create_app
from witness_api.settings import Settings
from witness_indexer.store import Store

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("WITNESS_LIVE") != "1", reason="set WITNESS_LIVE=1"),
]

LIVE_PG = os.environ.get("WITNESS_LIVE_PG",
                         "postgresql://postgres:witness@127.0.0.1:5432/postgres")
HORNET = os.environ.get("WITNESS_HORNET", "http://127.0.0.1:14265")
INX = os.environ.get("WITNESS_INX", "127.0.0.1:9029")
ROUTE_HOST = os.environ.get("WITNESS_ROUTE_HOST", "host.docker.internal")
KEYS = json.loads((Path(__file__).resolve().parents[2] / "core" / "tests" / "vectors"
                   / "coordinator_keys.json").read_text(encoding="utf-8"))["publicKeys"]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def reachable(addr: str) -> bool:
    host, _, port = addr.rpartition(":")
    try:
        with socket.create_connection((host, int(port)), timeout=2):
            return True
    except OSError:
        return False


async def wait_for(predicate, timeout_s: float = 15.0, step_s: float = 0.1):
    for _ in range(int(timeout_s / step_s)):
        value = await predicate()
        if value:
            return value
        await asyncio.sleep(step_s)
    return None


async def test_live_api_direct_and_through_the_node():
    schema = f"live_api_{uuid.uuid4().hex[:10]}"
    port = free_port()
    inx = INX if reachable(INX) else None
    settings = Settings(db=LIVE_PG, schema=schema, coordinator_keys=KEYS, threshold=2,
                        hornet_url=HORNET, inx_addr=inx, route_host=ROUTE_HOST, port=port,
                        validate=False)
    server = uvicorn.Server(uvicorn.Config(create_app(settings), host="127.0.0.1", port=port,
                                           loop="none", log_level="warning"))
    task = asyncio.create_task(server.serve())
    direct = f"http://127.0.0.1:{port}"
    node_url = f"{HORNET}/api/witness/v1"
    try:
        async def started():
            return server.started
        assert await wait_for(started), "uvicorn did not start"
        async with httpx.AsyncClient(timeout=10) as http:
            health = await http.get(f"{direct}/healthz")
            assert health.status_code == 200 and health.json()["db"] == "ok"
            cfg = (await http.get(f"{direct}/config/verifier")).json()
            assert cfg["network"] == "private_tangle1"
            assert cfg["trustedCoordinatorKeys"] == KEYS and cfg["threshold"] == 2

            if inx is None:
                pytest.skip(f"INX at {INX} is not reachable; direct port checked only")

            async def mounted():
                route = (await http.get(f"{direct}/stats")).json()["nodeRoute"]
                return route if route["registered"] else None
            route = await wait_for(mounted)
            assert route, "the node did not accept the route"
            assert route["url"] == node_url

            via_node = await http.get(f"{node_url}/healthz")
            assert via_node.status_code == 200, via_node.text
            assert via_node.json() == health.json()
            proxied_cfg = await http.get(f"{node_url}/config/verifier")
            assert proxied_cfg.json() == cfg
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 30)
        store = await Store.open(LIVE_PG, schema=schema)
        await store.drop_schema()
        await store.close()

    if inx is not None:  # shutdown unregistered the route
        async with httpx.AsyncClient(timeout=10) as http:
            assert (await http.get(f"{node_url}/healthz")).status_code == 404
