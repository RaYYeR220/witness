import asyncio

from fakechain import FakeChain, FakeSource
from witness_core import policy
from witness_indexer.maintenance import Every, Rescanner
from witness_indexer.pipeline import Indexer
from witness_indexer.rules import RulesEngine
from witness_indexer.store import Store


async def test_every_repeats_survives_failures_and_stops():
    calls = []

    async def fn():
        calls.append(len(calls))
        if len(calls) == 2:
            raise RuntimeError("one bad pass")

    every = Every("test", 0.01, fn)
    task = asyncio.create_task(every.run())
    while len(calls) < 4:
        await asyncio.sleep(0.01)
    await every.stop()
    await task
    assert every.runs >= 4


async def test_every_waits_for_a_pass_in_progress():
    entered, release, finished = asyncio.Event(), asyncio.Event(), []

    async def fn():
        entered.set()
        await release.wait()
        finished.append(True)

    every = Every("test", 60, fn, initial_delay_s=0)
    task = asyncio.create_task(every.run())
    await entered.wait()
    stopping = asyncio.create_task(every.stop())
    await asyncio.sleep(0.05)
    assert not stopping.done()
    release.set()
    await stopping
    await task
    assert finished == [True]


class RecordingRules:
    def __init__(self) -> None:
        self.calls: list[tuple[list[bytes], int | None]] = []

    async def rescan(self, ids, *, now_ms=None):
        self.calls.append((list(ids), now_ms))
        return []


def tagged_ids(chain: FakeChain, index: int) -> list[bytes]:
    return [b.block_id for b in chain.cones[index]][1 if index > 1 else 0:]


async def test_rescanner_reads_indexed_cones_from_the_source(store: Store):
    chain = FakeChain()
    for n in range(3):
        chain.add([("x", b"{}")] * (n + 1))
    await store.set_cursor(2)  # milestone 3 is not indexed yet
    rules = RecordingRules()
    rescan = Rescanner(FakeSource(chain), store, rules, batch=10, now_ms=lambda: 42)
    await rescan.run_once()
    assert rules.calls == [(tagged_ids(chain, 1) + tagged_ids(chain, 2), 42)]


async def test_rescanner_rotates_and_skips_unreadable_cones(store: Store):
    chain = FakeChain()
    for _ in range(3):
        chain.add([("x", b"{}")])
    await store.set_cursor(3)

    class Pruned(FakeSource):
        async def cone(self, index):
            if index == 2:
                raise RuntimeError("pruned")
            async for b in super().cone(index):
                yield b

    rules = RecordingRules()
    rescan = Rescanner(Pruned(chain), store, rules, batch=2)
    for _ in range(3):
        await rescan.run_once()
    assert [ids for ids, _ in rules.calls] == [
        tagged_ids(chain, 1), tagged_ids(chain, 3), tagged_ids(chain, 1)]


async def test_rescan_finds_rows_deleted_from_the_database(store: Store):
    chain = FakeChain()
    chain.add([("trust.score", b'{"id":"D:aabbccddeeff","score":0.5}'), ("x", b"{}")])
    pol = policy.load({"version": 1, "default": {"allowed": ["*"]}})
    rules = RulesEngine(store, None, None, pol)
    await Indexer(FakeSource(chain), store, rules=rules, policy=pol).sync()
    gone = chain.block_id(1, 1)
    await store._fetch("DELETE FROM messages WHERE block_id = %s RETURNING block_id", (gone,))
    new = await Rescanner(FakeSource(chain), store, rules).run_once()
    assert [(a.rule, a.block_id) for a in new] == [("MISSING_IN_DB", gone)]
    assert [a["rule"] for a in await store.alerts({"block_id": gone})] == ["MISSING_IN_DB"]
