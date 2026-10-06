"""A tiny in-memory Tangle for indexer tests: real block and milestone bytes, fake node."""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import AsyncIterator

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_core import codec, envelope, merkle
from witness_indexer.source import ConeBlock, MilestoneData, SourceUnavailable

COORDINATOR = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
GENESIS_TS = 1_790_000_000
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def did_key(sk: Ed25519PrivateKey) -> str:
    raw = b"\xed\x01" + sk.public_key().public_bytes_raw()
    n, out = int.from_bytes(raw, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "did:key:z" + out


def signed(sk: Ed25519PrivateKey, tag: str, body: dict | None, seq: int, *,
           mode: str = "producer", nonce: bytes | None = None, **kw) -> bytes:
    did = did_key(sk)
    env = envelope.seal(tag, body, iss=did, kid=f"{did}#{did[len('did:key:'):]}", sign_key=sk,
                        seq=seq, att_mode=mode, att_sub="user-1" if mode == "relay" else None,
                        now_ms=1_790_000_000_000 + seq, nonce=nonce or seq.to_bytes(16, "big"),
                        **kw)
    return json.dumps(env).encode()


def tamper(data: bytes, **changes) -> bytes:
    env = json.loads(data)
    env["body"].update(changes)
    return json.dumps(env).encode()


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def milestone_payload(index: int, ts: int, cone_ids: list[bytes], prev_id: bytes) -> bytes:
    parents = [cone_ids[-1]] if cone_ids else [bytes(32)]
    ess = codec.MilestoneEssence(index, ts, 2, prev_id, parents, merkle.root(cone_ids),
                                 bytes(32), b"", b"")
    eb = codec.serialize_milestone_essence(ess)
    sig = COORDINATOR.sign(codec.milestone_id(eb))
    pk = COORDINATOR.public_key().public_bytes_raw()
    return (codec.PAYLOAD_MILESTONE.to_bytes(4, "little") + eb + bytes([1, codec.SIG_ED25519])
            + pk + sig)


def milestone_block(payload: bytes, parent: bytes) -> bytes:
    return (bytes([2, 1]) + parent + len(payload).to_bytes(4, "little") + payload
            + bytes(8))


class FakeChain:
    """Milestones 1..n; the cone of milestone n starts with milestone n-1's block."""

    def __init__(self) -> None:
        self.ms: dict[int, MilestoneData] = {}
        self.cones: dict[int, list[ConeBlock]] = {}
        self._payloads: dict[int, bytes] = {}
        self._grew = asyncio.Event()

    @property
    def last(self) -> int:
        return max(self.ms, default=0)

    def add(self, payloads: list[tuple[str | bytes, bytes]] = (), *,
            ts: int | None = None) -> MilestoneData:
        index = self.last + 1
        raws = []
        if index > 1:
            raws.append(milestone_block(self._payloads[index - 1], bytes(32)))
        for i, (tag, data) in enumerate(payloads):
            tb = tag.encode() if isinstance(tag, str) else tag
            raws.append(codec.serialize_tagged_block([bytes(32)], tb, data,
                                                     nonce=index * 1000 + i))
        cone = [ConeBlock(codec.block_id(r), r, pos) for pos, r in enumerate(raws)]
        prev = self.ms[index - 1].id if index > 1 else bytes(32)
        payload = milestone_payload(index, ts if ts is not None else GENESIS_TS + 5 * index,
                                    [b.block_id for b in cone], prev)
        m = MilestoneData.from_payload(payload)
        self._payloads[index] = payload
        self.ms[index], self.cones[index] = m, cone
        self._grew.set()
        self._grew = asyncio.Event()
        return m

    def block_id(self, index: int, n: int) -> bytes:
        """Id of the n-th tagged block of milestone `index`."""
        return self.cones[index][n + (1 if index > 1 else 0)].block_id

    async def wait_for(self, index: int) -> None:
        while index not in self.ms:
            await self._grew.wait()


class FakeSource:
    name = "fake"

    def __init__(self, chain: FakeChain, *, fail_after: int | None = None,
                 tail: bool = False) -> None:
        self.chain = chain
        self.fail_after = fail_after
        self.tail = tail
        self.starts: list[int] = []
        self.closed = False

    async def milestones(self, start: int) -> AsyncIterator[MilestoneData]:
        self.starts.append(start)
        i = max(start, 1)
        while True:
            if i not in self.chain.ms:
                if not self.tail:
                    return
                await self.chain.wait_for(i)
            yield self.chain.ms[i]
            if self.fail_after == i:
                self.fail_after = None
                raise SourceUnavailable("connection reset by peer")
            i += 1

    async def cone(self, index: int) -> AsyncIterator[ConeBlock]:
        for b in self.chain.cones[index]:
            yield b

    async def close(self) -> None:
        self.closed = True
