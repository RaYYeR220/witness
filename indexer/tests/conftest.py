import asyncio
import os
import sys
import uuid

import pytest
import pytest_asyncio
from witness_indexer.store import Store

PG = os.environ.get("WITNESS_TEST_PG")


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
        reason="WITNESS_TEST_PG is unset; run `bash scripts/test-db.sh` and export it"
    )
    for item in items:
        if "store" in getattr(item, "fixturenames", ()):
            item.add_marker(skip)


@pytest_asyncio.fixture
async def store():
    """A migrated Store in a fresh, uniquely named schema, dropped afterwards."""
    schema = f"t_{uuid.uuid4().hex[:12]}"
    s = await Store.open(PG, schema=schema)
    await s.migrate()
    try:
        yield s
    finally:
        await s.drop_schema()
        await s.close()
