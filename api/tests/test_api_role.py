"""The API as its own read-mostly login (witness_api): it serves, ingests, runs node checks
and stores reports, and can do nothing else to the explorer's data."""

from dataclasses import replace
from pathlib import Path

import httpx
import psycopg
import pytest
import respx
from conftest import PG
from psycopg import errors, sql
from psycopg.conninfo import make_conninfo
from test_api_ingest import AUTH, hornet, make_block, record
from witness_api.app import create_app
from witness_core.ids import to_hex

GRANTS = (Path(__file__).resolve().parents[2] / "indexer" / "src" / "witness_indexer"
          / "migrations" / "0005_api_role.sql")
PASSWORD = "witness-api-test-password"


def _api_role(schema: str) -> str:
    """Create (or reset) witness_api, grant it this schema as migration 0005 does, and return
    its DSN."""
    with psycopg.connect(PG, autocommit=True) as admin:
        admin.execute(
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'witness_api') "
            "THEN CREATE ROLE witness_api; END IF; END $$")
        admin.execute(sql.SQL("ALTER ROLE witness_api WITH LOGIN PASSWORD {}").format(
            sql.Literal(PASSWORD)))
        admin.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        admin.execute(GRANTS.read_text(encoding="utf-8"))
    return make_conninfo(PG, user="witness_api", password=PASSWORD)


async def test_the_api_runs_on_its_own_role_without_migrating(store, settings):
    dsn = _api_role(store.schema)
    raw, bid, data = make_block()
    app = create_app(replace(settings, db=dsn, migrate=False))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://w.test") as c:
            assert (await c.get("/healthz")).status_code == 200
            ingest = await c.post("/ingest", json=record("sub-1", bid, data), headers=AUTH)
            assert ingest.status_code == 202, ingest.text
            with respx.mock() as mock:
                hornet(mock, bid, raw)
                v = await c.post(f"/messages/{to_hex(bid)}/verify")
            assert v.status_code == 200, v.text
            assert v.json()["status"] == "CONTENT_VERIFIED"
            assert (await c.get("/messages")).status_code == 200
            assert (await c.get("/alerts")).status_code == 200


@pytest.mark.parametrize("statement", [
    "DELETE FROM messages",
    "UPDATE messages SET data = ''::bytea",
    "UPDATE alerts SET severity = 'low'",
    "INSERT INTO cursor (id, ms) VALUES (1, 0)",
    "TRUNCATE events",
    "CREATE TABLE intruder (a int)",
    "DROP TABLE reports",
])
async def test_the_api_role_cannot_change_anything_else(store, statement):
    dsn = _api_role(store.schema)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(store.schema)))
        conn.execute("SELECT count(*) FROM messages")  # reading is fine
        with pytest.raises(errors.InsufficientPrivilege):
            conn.execute(statement)
