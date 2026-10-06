"""Mount the API on the HORNET node: INX `RegisterAPIRoute` makes the node proxy
`/api/<route>/*` to this server, so `:14265/api/witness/v1/...` answers like `:7200/...`.

The request is a single `inx.APIRouteRequest {route=1, host=2, port=3, path=4}`; it is
encoded here directly so the mount does not depend on generated INX stubs. Any failure is
logged and leaves the API serving on its own port.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

log = logging.getLogger(__name__)

REGISTER = "/inx.INX/RegisterAPIRoute"
UNREGISTER = "/inx.INX/UnregisterAPIRoute"


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _text(field: int, value: str) -> bytes:
    raw = value.encode("utf-8")
    return bytes([field << 3 | 2]) + _varint(len(raw)) + raw if raw else b""


def encode_route_request(route: str, host: str = "", port: int = 0, path: str = "") -> bytes:
    """Protobuf encoding of `inx.APIRouteRequest` (proto3: default values are omitted)."""
    if not 0 <= port <= 65535:
        raise ValueError(f"port {port} out of range")
    port_field = bytes([3 << 3 | 0]) + _varint(port) if port else b""
    return _text(1, route) + _text(2, host) + port_field + _text(4, path)


def _import_grpc() -> Any:
    import grpc  # deferred: only needed when the API is mounted on a node

    return grpc


class NodeRoute:
    """One API route registered on a node over INX."""

    def __init__(self, inx_addr: str, route: str, host: str, port: int, *,
                 timeout_s: float = 5.0, retry_max_s: float = 60.0) -> None:
        self.inx_addr = inx_addr
        self.route = route
        self.host = host
        self.port = port
        self.timeout_s = timeout_s
        self.retry_max_s = retry_max_s
        self.registered = False
        self.error: str | None = None
        self._unavailable = False  # grpc missing: retrying cannot help
        self._task: asyncio.Task | None = None

    async def _call(self, method: str, request: bytes) -> None:
        grpc = _import_grpc()
        async with grpc.aio.insecure_channel(self.inx_addr) as channel:
            await asyncio.wait_for(channel.channel_ready(), self.timeout_s)
            call = channel.unary_unary(method)  # bytes in, bytes out
            await call(request, timeout=self.timeout_s)

    async def register(self, *, level: int = logging.WARNING) -> bool:
        """Ask the node to proxy `/api/<route>/*` here. Never raises."""
        request = encode_route_request(self.route, self.host, self.port)
        try:
            await self._call(REGISTER, request)
        except ImportError as e:
            self.error, self._unavailable = f"grpc is not installed ({e})", True
            log.warning("cannot mount /api/%s on the node: %s; serving on port %d only",
                        self.route, self.error, self.port)
            return False
        except Exception as e:  # noqa: BLE001 - any INX failure leaves the direct port working
            self.error = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
            log.log(level, "could not register /api/%s on the node at %s: %s; serving on port "
                    "%d only", self.route, self.inx_addr, self.error, self.port)
            return False
        self.registered, self.error = True, None
        log.info("node at %s now proxies /api/%s to %s:%d", self.inx_addr, self.route,
                 self.host, self.port)
        return True

    async def unregister(self) -> None:
        """Remove the route if this process registered it. Never raises."""
        if not self.registered:
            return
        try:
            await self._call(UNREGISTER, encode_route_request(self.route))
        except Exception as e:  # noqa: BLE001 - shutting down regardless
            log.warning("could not unregister /api/%s from the node: %s", self.route, e)
        self.registered = False

    async def _keep_trying(self) -> None:
        delay, level = 1.0, logging.WARNING
        while not await self.register(level=level) and not self._unavailable:
            await asyncio.sleep(delay)
            delay, level = min(delay * 2, self.retry_max_s), logging.DEBUG

    def start(self) -> None:
        """Register in the background, retrying until the node accepts the route."""
        if self._task is None:
            self._task = asyncio.create_task(self._keep_trying(), name="node-route")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        await self.unregister()
