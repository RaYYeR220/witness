"""What the indexer reads from a node: confirmed milestones and their white-flag cones.

Two implementations exist: `source_inx.InxSource` (gRPC, streams) and
`source_rest.RestSource` (core REST API, polling). Both hand out the same value types.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Protocol

from witness_core import codec


class SourceUnavailable(Exception):
    """The node cannot be reached or the connection broke; the caller may retry."""


class SourceError(Exception):
    """The node answered with data that does not add up (bad id, broken cone)."""


class ConeMismatch(SourceError):
    """A milestone's cone does not hash to the milestone's inclusion Merkle root."""


class NetworkChanged(SourceError):
    """The node's milestones do not continue the chain already in the database."""


@dataclass(frozen=True)
class MilestoneData:
    index: int
    id: bytes
    timestamp: int  # seconds
    essence: bytes  # exactly the signed bytes; `id` is BLAKE2b-256 of them
    signatures: list[codec.Ed25519Sig]
    inclusion_root: bytes
    prev_id: bytes
    parents: list[bytes]

    @classmethod
    def from_payload(cls, raw_payload: bytes) -> MilestoneData:
        """Build from a serialized milestone payload (leading u32 type word included)."""
        p = codec.parse_milestone_payload(raw_payload)
        e = p.essence
        return cls(
            index=e.index,
            id=codec.milestone_id(p.essence_bytes),
            timestamp=e.timestamp,
            essence=p.essence_bytes,
            signatures=list(p.signatures),
            inclusion_root=e.inclusion_merkle_root,
            prev_id=e.previous_milestone_id,
            parents=list(e.parents),
        )

    def signature_dicts(self) -> list[dict]:
        return [{"pk": "0x" + s.public_key.hex(), "sig": "0x" + s.signature.hex()}
                for s in self.signatures]


@dataclass(frozen=True)
class ConeBlock:
    block_id: bytes
    raw: bytes
    wf_index: int


class BlockSource(Protocol):
    name: str

    def milestones(self, start: int) -> AsyncIterator[MilestoneData]:
        """Confirmed milestones from `start` on: the backlog first, then new ones as they
        are confirmed. Raises SourceUnavailable when the node goes away."""
        ...

    def cone(self, index: int) -> AsyncIterator[ConeBlock]:
        """Blocks referenced by milestone `index`, in white-flag order."""
        ...

    async def close(self) -> None: ...


def check_cone(index: int, blocks: list[ConeBlock]) -> list[ConeBlock]:
    """Sort a cone by white-flag index and make sure it is complete and self-consistent."""
    out = sorted(blocks, key=lambda b: b.wf_index)
    for pos, b in enumerate(out):
        if b.wf_index != pos:
            raise SourceError(f"milestone {index}: white-flag indexes are not 0..{len(out) - 1}")
        if codec.block_id(b.raw) != b.block_id:
            raise SourceError(f"milestone {index}: block 0x{b.block_id.hex()} does not hash "
                              "to its id")
    return out
