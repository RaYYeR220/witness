import json
from pathlib import Path

import httpx
import pytest
import respx
from witness_core import codec, merkle
from witness_indexer.source import ConeBlock, SourceError, SourceUnavailable
from witness_indexer.source_rest import RAW, RestSource

VECTORS = Path(__file__).resolve().parents[2] / "core" / "tests" / "vectors"
BASE = "http://hornet.test"


def load(name: str):
    return json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))


def unhex(s: str) -> bytes:
    return bytes.fromhex(s[2:])


def payload_of(m: dict) -> bytes:
    sigs = b"".join(b"\x00" + unhex(s["pk"]) + unhex(s["sig"]) for s in m["signatures"])
    return (b"\x07\x00\x00\x00" + unhex(m["essence"]) + bytes([len(m["signatures"])]) + sigs)


class FakeHornet:
    """HORNET's core REST API over the captured vectors (milestones 371..373 complete)."""

    def __init__(self, confirmed: int = 373, pruning: int = 370) -> None:
        self.milestones = {m["index"]: m for m in load("milestones")}
        self.raw = {b["blockId"]: unhex(b["raw"]) for b in load("blocks")}
        self.meta: dict[str, dict] = {}
        for cone in load("cones"):
            for pos, bid in enumerate(cone["blockIdsWhiteFlagOrder"]):
                md = {"blockId": bid, "isSolid": True,
                      "referencedByMilestoneIndex": cone["index"], "whiteFlagIndex": pos}
                if bid in self.raw:
                    md["parents"] = ["0x" + p.hex()
                                     for p in codec.parse_block(self.raw[bid]).parents]
                self.meta[bid] = md
        self.cones = {c["index"]: c["blockIdsWhiteFlagOrder"] for c in load("cones")}
        self.info = [{"status": {"confirmedMilestone": {"index": confirmed},
                                 "pruningIndex": pruning}}]
        self.requests: list[str] = []

    def mount(self, router: respx.MockRouter) -> None:
        router.get("/api/core/v2/info").mock(side_effect=self._info)
        router.get(url__regex=r"/api/core/v2/milestones/by-index/(?P<i>\d+)$").mock(
            side_effect=self._milestone)
        router.get(url__regex=r"/api/core/v2/blocks/(?P<bid>0x[0-9a-f]+)/metadata$").mock(
            side_effect=self._metadata)
        router.get(url__regex=r"/api/core/v2/blocks/(?P<bid>0x[0-9a-f]+)$").mock(
            side_effect=self._block)

    def _info(self, request):
        body = self.info[0] if len(self.info) == 1 else self.info.pop(0)
        return httpx.Response(200, json=body)

    def _milestone(self, request, i):
        m = self.milestones.get(int(i))
        if m is None:
            return httpx.Response(404, json={"error": {"code": "404"}})
        assert request.headers["accept"] == RAW
        return httpx.Response(200, content=payload_of(m))

    def _metadata(self, request, bid):
        self.requests.append(f"meta {bid}")
        md = self.meta.get(bid)
        return httpx.Response(200, json=md) if md else httpx.Response(404)

    def _block(self, request, bid):
        self.requests.append(f"raw {bid}")
        assert request.headers["accept"] == RAW
        raw = self.raw.get(bid)
        return httpx.Response(200, content=raw) if raw is not None else httpx.Response(404)


async def take(aiter, n: int) -> list:
    out = []
    async for item in aiter:
        out.append(item)
        if len(out) == n:
            break
    await aiter.aclose()
    return out


async def test_rest_source_from_vectors():
    node = FakeHornet()
    async with respx.mock(base_url=BASE, assert_all_called=False) as router:
        node.mount(router)
        src = RestSource(BASE, poll_s=0)
        got = await take(src.milestones(1), 3)  # backlog starts after the pruning index
        assert [m.index for m in got] == [371, 372, 373]
        for m in got:
            v = node.milestones[m.index]
            assert m.id == unhex(v["milestoneId"])
            assert m.timestamp == v["timestamp"]
            assert m.essence == unhex(v["essence"])
            assert [(s.public_key, s.signature) for s in m.signatures] == [
                (unhex(s["pk"]), unhex(s["sig"])) for s in v["signatures"]]
            assert m.inclusion_root == unhex(v["inclusionMerkleRoot"])
            assert m.prev_id == unhex(v["previousMilestoneId"])

            cone = [b async for b in src.cone(m.index)]
            assert cone == [ConeBlock(unhex(bid), node.raw[bid], pos)
                            for pos, bid in enumerate(node.cones[m.index])]
            assert merkle.root([b.block_id for b in cone]) == m.inclusion_root
        await src.close()


async def test_rest_cone_without_a_cached_milestone():
    node = FakeHornet()
    async with respx.mock(base_url=BASE, assert_all_called=False) as router:
        node.mount(router)
        async with RestSource(BASE) as src:
            cone = [b.block_id for b in [b async for b in src.cone(372)]]
        assert cone == [unhex(b) for b in node.cones[372]]
        # the walk stops at blocks an older milestone referenced
        assert not any(r.startswith("raw") and r[4:] in node.cones[371] for r in node.requests)


async def test_rest_source_tails_new_milestones():
    node = FakeHornet(confirmed=371)
    node.info.append({"status": {"confirmedMilestone": {"index": 371}, "pruningIndex": 0}})
    node.info.append({"status": {"confirmedMilestone": {"index": 373}, "pruningIndex": 0}})
    sleeps = []

    async def sleep(s):
        sleeps.append(s)

    async with respx.mock(base_url=BASE, assert_all_called=False) as router:
        node.mount(router)
        src = RestSource(BASE, poll_s=1.0, sleep=sleep)
        got = await take(src.milestones(371), 3)
    assert [m.index for m in got] == [371, 372, 373]
    assert sleeps == [1.0, 1.0]


async def test_rest_source_skips_a_milestone_pruned_meanwhile():
    node = FakeHornet(confirmed=373, pruning=0)
    del node.milestones[372]
    async with respx.mock(base_url=BASE, assert_all_called=False) as router:
        node.mount(router)
        got = await take(RestSource(BASE).milestones(371), 2)
    assert [m.index for m in got] == [371, 373]


async def test_rest_source_unreachable():
    async with respx.mock(base_url=BASE) as router:
        router.get("/api/core/v2/info").mock(side_effect=httpx.ConnectError("refused"))
        src = RestSource(BASE)
        with pytest.raises(SourceUnavailable):
            await take(src.milestones(1), 1)
        with pytest.raises(SourceUnavailable):
            await src.connect()


async def test_rest_cone_with_a_wrong_block_is_refused():
    node = FakeHornet()
    bid = node.cones[372][1]
    node.raw[bid] = node.raw[bid][:-1] + b"\x01"
    async with respx.mock(base_url=BASE, assert_all_called=False) as router:
        node.mount(router)
        with pytest.raises(SourceError):
            [b async for b in RestSource(BASE).cone(372)]
