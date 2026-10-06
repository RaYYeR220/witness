"""InxSource against an in-process INX server that serves a FakeChain."""

import asyncio

import grpc
import pytest
from fakechain import FakeChain
from witness_indexer.inx_proto import inx_pb2 as pb
from witness_indexer.inx_proto import inx_pb2_grpc as rpc
from witness_indexer.source import SourceError, SourceUnavailable
from witness_indexer.source_inx import InxSource


class FakeInx(rpc.INXServicer):
    def __init__(self, chain: FakeChain, pruning: int = 0) -> None:
        self.chain = chain
        self.pruning = pruning
        self.range_requests: list[tuple[int, int]] = []
        self.routes: list[tuple[str, str, int, str]] = []
        self.unregistered: list[str] = []
        self.corrupt: int | None = None

    def _ms(self, i: int) -> pb.Milestone:
        m = self.chain.ms[i]
        return pb.Milestone(
            milestone_info=pb.MilestoneInfo(milestone_id=pb.MilestoneId(id=m.id),
                                            milestone_index=i, milestone_timestamp=m.timestamp),
            milestone=pb.RawMilestone(data=self.chain._payloads[i]))

    async def ReadNodeStatus(self, request, context):
        return pb.NodeStatus(is_healthy=True, is_synced=True,
                             confirmed_milestone=self._ms(self.chain.last),
                             tangle_pruning_index=self.pruning,
                             milestones_pruning_index=self.pruning)

    async def ListenToConfirmedMilestones(self, request, context):
        self.range_requests.append((request.start_milestone_index,
                                    request.end_milestone_index))
        i = request.start_milestone_index
        while True:
            await self.chain.wait_for(i)
            yield pb.MilestoneAndProtocolParameters(milestone=self._ms(i))
            i += 1

    async def ReadMilestoneCone(self, request, context):
        i = request.milestone_index
        for b in reversed(self.chain.cones[i]):  # order must not matter to the client
            raw = b.raw if self.corrupt != b.wf_index else b.raw + b"\x00"
            yield pb.BlockWithMetadata(
                metadata=pb.BlockMetadata(block_id=pb.BlockId(id=b.block_id),
                                          referenced_by_milestone_index=i,
                                          white_flag_index=b.wf_index),
                block=pb.RawBlock(data=raw))

    async def RegisterAPIRoute(self, request, context):
        self.routes.append((request.route, request.host, request.port, request.path))
        return pb.NoParams()

    async def UnregisterAPIRoute(self, request, context):
        self.unregistered.append(request.route)
        return pb.NoParams()


@pytest.fixture
async def node():
    chain = FakeChain()
    for n in range(3):
        chain.add([("trust.score", b'{"id":"D:aabbccddeeff","score":0.5}')] * (n + 1))
    servicer = FakeInx(chain)
    server = grpc.aio.server()
    rpc.add_INXServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    try:
        yield chain, servicer, server, f"127.0.0.1:{port}"
    finally:
        await server.stop(0)


async def take(aiter, n: int) -> list:
    out = []
    async for item in aiter:
        out.append(item)
        if len(out) == n:
            break
    await aiter.aclose()
    return out


async def test_inx_streams_milestones_and_cones(node):
    chain, servicer, _, addr = node
    async with InxSource(addr) as src:
        got = await take(src.milestones(1), 3)
        assert got == [chain.ms[i] for i in (1, 2, 3)]
        assert servicer.range_requests == [(1, 0)]
        for i in (1, 2, 3):
            assert [b async for b in src.cone(i)] == chain.cones[i]


async def test_inx_tails_new_milestones(node):
    chain, _, _, addr = node
    async with InxSource(addr) as src:
        stream = src.milestones(3)
        assert (await anext(stream)).index == 3
        nxt = asyncio.ensure_future(anext(stream))
        await asyncio.sleep(0.05)
        assert not nxt.done()
        chain.add([])
        assert (await asyncio.wait_for(nxt, 5)).index == 4
        await stream.aclose()


async def test_inx_starts_after_the_pruning_index(node):
    _, servicer, _, addr = node
    servicer.pruning = 1
    async with InxSource(addr) as src:
        assert [m.index for m in await take(src.milestones(1), 2)] == [2, 3]
    assert servicer.range_requests == [(2, 0)]


async def test_inx_rejects_a_block_that_does_not_match_its_id(node):
    _, servicer, _, addr = node
    servicer.corrupt = 1
    async with InxSource(addr) as src:
        with pytest.raises(SourceError):
            [b async for b in src.cone(2)]


async def test_inx_unreachable():
    src = InxSource("127.0.0.1:1", connect_timeout_s=0.3)
    with pytest.raises(SourceUnavailable):
        await src.connect()
    with pytest.raises(SourceUnavailable):
        await take(src.milestones(1), 1)
    await src.close()


async def test_inx_node_going_away_mid_stream(node):
    _, _, server, addr = node
    async with InxSource(addr) as src:
        stream = src.milestones(1)
        assert (await anext(stream)).index == 1
        await server.stop(0)
        with pytest.raises(SourceUnavailable):
            async for _ in stream:
                pass


async def test_inx_route_registration(node):
    _, servicer, _, addr = node
    async with InxSource(addr) as src:
        await src.register_route("witness/v1", "host.docker.internal", 7400)
        await src.unregister_route("witness/v1")
    assert servicer.routes == [("witness/v1", "host.docker.internal", 7400, "")]
    assert servicer.unregistered == ["witness/v1"]
