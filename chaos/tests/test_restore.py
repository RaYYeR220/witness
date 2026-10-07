"""A19 leaves the eval database as it found it: exact restore, after interruptions too."""

import json
import sys
import types

import pytest
from witness_chaos import attacks as A
from witness_chaos import runner as R

BID = bytes.fromhex("cd" * 32)


class FakeDb:
    """`messages.data` by block id, with the two statements restore_rows uses."""

    def __init__(self, rows, sticky=None):
        self.rows = dict(rows)
        self.sticky = sticky or {}  # block -> bytes a concurrent writer keeps putting back

    async def execute(self, sql, params):
        db = self

        class Cur:
            def __init__(self, row):
                self.row = row

            async def fetchone(self):
                return self.row

        if sql == A.RESTORE_SQL:
            data, bid = params
            db.rows[bid] = db.sticky.get(bid, data)
            return Cur(None)
        if sql == A.READ_DATA_SQL:
            (bid,) = params
            return Cur((db.rows[bid],) if bid in db.rows else None)
        raise AssertionError(sql)


async def test_restore_puts_back_the_exact_bytes_and_checks_them():
    db = FakeDb({BID: b"tampered"})
    assert await A.restore_rows(db, {BID: b"original"}) == [{"block": "0x" + "cd" * 32,
                                                            "ok": True}]
    assert db.rows[BID] == b"original"


async def test_restore_reports_a_row_that_does_not_read_back():
    db = FakeDb({BID: b"tampered"}, sticky={BID: b"someone else"})
    assert await A.restore_rows(db, {BID: b"original"}) == [{"block": "0x" + "cd" * 32,
                                                            "ok": False}]


def test_tamper_log_round_trip_and_hash_check(tmp_path):
    log = tmp_path / "tampered.jsonl"
    A.log_original(log, BID, b"original")
    A.log_original(log, BID, b"later state")  # a second entry never replaces the first
    assert A.read_tamper_log(log) == {BID: b"original"}
    entry = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    entry["original"] = b"forged".hex()
    log.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        A.read_tamper_log(log)


def _fake_psycopg(monkeypatch, db):
    class Conn:
        async def __aenter__(self):
            return db

        async def __aexit__(self, *a):
            return False

    class AsyncConnection:
        @staticmethod
        async def connect(dsn, autocommit):
            return Conn()

    conninfo = types.SimpleNamespace(
        conninfo_to_dict=lambda dsn: {"host": "127.0.0.1"},
        make_conninfo=lambda dsn, options: dsn)
    monkeypatch.setitem(sys.modules, "psycopg", types.SimpleNamespace(
        AsyncConnection=AsyncConnection, conninfo=conninfo))
    monkeypatch.setitem(sys.modules, "psycopg.conninfo", conninfo)


def test_restore_command_replays_the_log_and_is_idempotent(tmp_path, monkeypatch, capsys):
    A.log_original(tmp_path / R.TAMPER_LOG, BID, b"original")
    db = FakeDb({BID: b"tampered"})
    _fake_psycopg(monkeypatch, db)
    assert R.restore_command(tmp_path, "postgresql://127.0.0.1/witness", "witness", False) == 0
    assert db.rows[BID] == b"original"
    assert R.restore_command(tmp_path, "postgresql://127.0.0.1/witness", "witness", False) == 0
    assert db.rows[BID] == b"original"


def test_restore_command_refuses_a_remote_database(tmp_path, monkeypatch):
    A.log_original(tmp_path / R.TAMPER_LOG, BID, b"original")
    conninfo = types.SimpleNamespace(conninfo_to_dict=lambda dsn: {"host": "db.example"},
                                     make_conninfo=lambda dsn, options: dsn)
    monkeypatch.setitem(sys.modules, "psycopg.conninfo", conninfo)
    assert R.restore_command(tmp_path, "postgresql://db.example/w", "witness", False) == 2


async def test_an_interrupted_run_still_restores(tmp_path, monkeypatch):
    cfg = R.RunConfig(api="http://127.0.0.1:7200", relay="http://127.0.0.1:5557",
                      orion="http://127.0.0.1:1026", hornet="http://127.0.0.1:14265",
                      out=str(tmp_path / "out"), trap=False, allow_nonlocal=True)
    r = R.Runner(cfg)
    calls = []

    async def nothing(*a, **k):
        return {}

    ctx = A.AttackContext(live=True, producer=types.SimpleNamespace(iss="did:key:zRun"))

    async def boom(*a, **k):
        raise RuntimeError("interrupted")

    async def restore():
        calls.append("restore")
        return [{"block": "0x" + "cd" * 32, "ok": True}]

    monkeypatch.setattr(r, "preflight", nothing)
    monkeypatch.setattr(r, "build_context", lambda: ctx)
    monkeypatch.setattr(r, "check_identity", nothing)
    monkeypatch.setattr(r, "check_exclusive", nothing)
    monkeypatch.setattr(r, "classes", lambda: [{"id": "A19"}])
    monkeypatch.setattr(r, "run_class", boom)
    monkeypatch.setattr(r, "restore_tampered", restore)
    with pytest.raises(RuntimeError, match="interrupted"):
        await r.run()
    assert calls == ["restore"]
    meta = json.loads((tmp_path / "out" / "run.json").read_text(encoding="utf-8"))
    assert meta["restored"] == [{"block": "0x" + "cd" * 32, "ok": True}]
    assert meta["restoreFailed"] == []


async def test_a_failing_restore_is_recorded_with_every_row_left(tmp_path, monkeypatch):
    cfg = R.RunConfig(api="http://127.0.0.1:7200", relay="http://127.0.0.1:5557",
                      orion="http://127.0.0.1:1026", hornet="http://127.0.0.1:14265",
                      out=str(tmp_path / "out"), trap=False, allow_nonlocal=True)
    r = R.Runner(cfg)

    async def nothing(*a, **k):
        return {}

    ctx = A.AttackContext(live=True, producer=types.SimpleNamespace(iss="did:key:zRun"))
    ctx.originals[BID] = b"original"

    async def db_down():
        raise OSError("connection refused")

    monkeypatch.setattr(r, "preflight", nothing)
    monkeypatch.setattr(r, "build_context", lambda: ctx)
    monkeypatch.setattr(r, "check_identity", nothing)
    monkeypatch.setattr(r, "check_exclusive", nothing)
    monkeypatch.setattr(r, "classes", list)
    monkeypatch.setattr(r, "late_sweep", nothing)
    monkeypatch.setattr(r, "restore_tampered", db_down)
    card = await r.run()
    assert card["restoreFailed"] == ["0x" + "cd" * 32]
    meta = json.loads((tmp_path / "out" / "run.json").read_text(encoding="utf-8"))
    assert meta["restoreFailed"] == ["0x" + "cd" * 32]
