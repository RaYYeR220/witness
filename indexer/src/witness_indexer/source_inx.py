"""Milestones and cones streamed from the node over INX (gRPC), plus API route registration.

`ListenToConfirmedMilestones` delivers the backlog from the requested index and then every
new confirmed milestone; `ReadMilestoneCone` delivers the blocks a milestone referenced with
their white-flag index. `RegisterAPIRoute` makes the node proxy `/api/<route>/*` to us.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import Self

import grpc

from .inx_proto import inx_pb2 as pb
from .inx_proto import inx_pb2_grpc as rpc
from .source import ConeBlock, MilestoneData, SourceError, SourceUnavailable, check_cone

log = logging.getLogger(__name__)


def _unavailable(addr: str, e: grpc.aio.AioRpcError) -> SourceUnavailable:
    return SourceUnavailable(f"INX {addr}: {e.code().name}: {e.details()}")


class InxSource:
    name = "inx"

    def __init__(self, addr: str, *, connect_timeout_s: float = 5.0) -> None:
        self.addr = addr
        self.connect_timeout_s = connect_timeout_s
        self._channel: grpc.aio.Channel | None = None
        self._stub: rpc.INXStub | None = None

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def connect(self) -> None:
        """Open the channel; raise SourceUnavailable if the node does not answer in time."""
        if self._stub is not None:
            return
        channel = grpc.aio.insecure_channel(self.addr)
        try:
            await asyncio.wait_for(channel.channel_ready(), self.connect_timeout_s)
        except (TimeoutError, grpc.aio.AioRpcError) as e:
            await channel.close()
            raise SourceUnavailable(f"INX {self.addr} not reachable "
                                    f"within {self.connect_timeout_s:g} s") from e
        self._channel, self._stub = channel, rpc.INXStub(channel)

    async def close(self) -> None:
        if self._channel is not None:
            channel, self._channel, self._stub = self._channel, None, None
            await channel.close()

    async def _ready(self) -> rpc.INXStub:
        await self.connect()
        assert self._stub is not None
        return self._stub

    async def node_status(self) -> pb.NodeStatus:
        stub = await self._ready()
        try:
            return await stub.ReadNodeStatus(pb.NoParams())
        except grpc.aio.AioRpcError as e:
            raise _unavailable(self.addr, e) from e

    # -- BlockSource ------------------------------------------------------------------------

    async def milestones(self, start: int) -> AsyncIterator[MilestoneData]:
        status = await self.node_status()
        pruned = max(status.tangle_pruning_index, status.milestones_pruning_index)
        index = max(start, 1)
        if index <= pruned:
            log.warning("milestones up to %d are pruned on the node; starting at %d",
                        pruned, pruned + 1)
            index = pruned + 1
        confirmed = status.confirmed_milestone.milestone_info.milestone_index
        if index > confirmed + 1:
            log.warning("waiting for milestone %d; the node has only confirmed %d "
                        "(was the network reset under an existing database?)", index, confirmed)

        stub = await self._ready()
        call = stub.ListenToConfirmedMilestones(
            pb.MilestoneRangeRequest(start_milestone_index=index, end_milestone_index=0))
        try:
            async for msg in call:
                info = msg.milestone.milestone_info
                m = MilestoneData.from_payload(msg.milestone.milestone.data)
                if m.index != info.milestone_index or (
                        info.HasField("milestone_id") and m.id != info.milestone_id.id):
                    raise SourceError(f"INX milestone {info.milestone_index}: payload does "
                                      "not match its index/id")
                yield m
        except grpc.aio.AioRpcError as e:
            raise _unavailable(self.addr, e) from e
        finally:
            call.cancel()

    async def cone(self, index: int) -> AsyncIterator[ConeBlock]:
        stub = await self._ready()
        blocks = []
        try:
            async for b in stub.ReadMilestoneCone(pb.MilestoneRequest(milestone_index=index)):
                md = b.metadata
                if md.referenced_by_milestone_index != index:
                    raise SourceError(f"INX cone of {index} holds a block referenced by "
                                      f"{md.referenced_by_milestone_index}")
                blocks.append(ConeBlock(md.block_id.id, b.block.data, md.white_flag_index))
        except grpc.aio.AioRpcError as e:
            raise _unavailable(self.addr, e) from e
        for b in check_cone(index, blocks):
            yield b

    # -- REST route on the node -------------------------------------------------------------

    async def register_route(self, route: str, host: str, port: int, path: str = "") -> None:
        """Have the node proxy `/api/<route>/*` to http://host:port<path>/*."""
        stub = await self._ready()
        try:
            await stub.RegisterAPIRoute(
                pb.APIRouteRequest(route=route, host=host, port=port, path=path))
        except grpc.aio.AioRpcError as e:
            raise _unavailable(self.addr, e) from e

    async def unregister_route(self, route: str) -> None:
        stub = await self._ready()
        try:
            await stub.UnregisterAPIRoute(pb.APIRouteRequest(route=route))
        except grpc.aio.AioRpcError as e:
            raise _unavailable(self.addr, e) from e
