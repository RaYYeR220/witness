import asyncio
import json
import os
import sys
import uuid
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from witness_api.app import create_app
from witness_api.settings import Settings
from witness_api.store import ExplorerStore

PG = os.environ.get("WITNESS_TEST_PG")
VECTORS = Path(__file__).resolve().parents[2] / "core" / "tests" / "vectors"

HORNET = "http://hornet.test"
ANCHOR = "http://anchor.test"
ORION = "http://orion.test"
TOKEN = "test-ingest-token-0123456789"
TRAIL = "0x" + "7a" * 32


@pytest.fixture(scope="session")
def event_loop_policy():
    # psycopg's async mode cannot run on the Windows default (Proactor) loop.
    if sys.platform == "win32":
        return asyncio.WindowsSelectorEventLoopPolicy()
    return asyncio.DefaultEventLoopPolicy()


def pytest_collection_modifyitems(config, items):
    if PG:
        return
    skip = pytest.mark.skip(
        reason="WITNESS_TEST_PG is unset; run `bash scripts/test-db.sh` and export it")
    for item in items:
        if "store" in getattr(item, "fixturenames", ()):
            item.add_marker(skip)


@pytest.fixture(scope="session")
def vectors():
    def load(name: str):
        return json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))
    return load


@pytest_asyncio.fixture
async def store():
    """A migrated store in a fresh, uniquely named schema, dropped afterwards."""
    schema = f"t_{uuid.uuid4().hex[:12]}"
    s = await ExplorerStore.open(PG, schema=schema)
    await s.migrate()
    try:
        yield s
    finally:
        await s.drop_schema()
        await s.close()


@pytest.fixture
def settings(store, vectors):
    keys = vectors("coordinator_keys")["publicKeys"]
    return Settings(
        db=PG, schema=store.schema, network="private_tangle1", coordinator_keys=keys,
        threshold=2, orion_url=ORION, anchor_url=ANCHOR, hornet_url=HORNET, inx_addr=None,
        public_base_url=None, cors_origins=["http://console.test"], ingest_token=TOKEN,
        rebased_network="testnet", trail_id=TRAIL, validate=False, verify_timeout_s=3.0,
    )


@pytest_asyncio.fixture
async def app(settings, store):
    application = create_app(settings, store=store)
    async with application.router.lifespan_context(application):
        yield application


@pytest_asyncio.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://witness.test") as c:
        yield c
