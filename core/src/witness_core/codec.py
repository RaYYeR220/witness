"""Binary codec for IOTA Stardust blocks, tagged data and milestones.

Layouts follow TIP-24 (block), TIP-23 (tagged data) and TIP-29 (milestone).
All integers are little-endian. Pure functions, no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass

from .ids import blake2b256

PAYLOAD_TAGGED_DATA = 5
PAYLOAD_MILESTONE = 7
SIG_ED25519 = 0
ID_LEN = 32
PUBKEY_LEN = 32
SIG_LEN = 64
# The only milestone option type this codec can measure (TIP-29 protocol params).
OPT_PROTOCOL_PARAMS = 4
_OPT_HEADER = 8  # type u8 | targetMilestoneIndex u32 | protocolVersion u8 | paramsLength u16


class DecodeError(ValueError):
    """Raised when bytes do not form a valid Stardust structure."""


@dataclass(frozen=True)
class TaggedData:
    tag: bytes
    data: bytes


@dataclass(frozen=True)
class Ed25519Sig:
    public_key: bytes
    signature: bytes


@dataclass(frozen=True)
class MilestoneEssence:
    index: int
    timestamp: int
    protocol_version: int
    previous_milestone_id: bytes
    parents: list[bytes]
    inclusion_merkle_root: bytes
    applied_merkle_root: bytes
    metadata: bytes
    # Raw bytes after the optionsCount byte; the count is re-derived on write.
    options: bytes


@dataclass(frozen=True)
class MilestonePayload:
    essence: MilestoneEssence
    essence_bytes: bytes
    signatures: list[Ed25519Sig]


@dataclass(frozen=True)
class OtherPayload:
    type: int
    raw: bytes


@dataclass(frozen=True)
class Block:
    protocol_version: int
    parents: list[bytes]
    payload: TaggedData | MilestonePayload | OtherPayload | None
    nonce: int


class _Reader:
    def __init__(self, buf: bytes, what: str) -> None:
        self.buf = buf
        self.pos = 0
        self.what = what

    def take(self, n: int, field: str) -> bytes:
        if self.pos + n > len(self.buf):
            raise DecodeError(
                f"{self.what}: truncated reading {field} "
                f"(need {n} bytes at offset {self.pos}, have {len(self.buf) - self.pos})"
            )
        out = self.buf[self.pos : self.pos + n]
        self.pos += n
        return out

    def uint(self, n: int, field: str) -> int:
        return int.from_bytes(self.take(n, field), "little")

    def finish(self) -> None:
        if self.pos != len(self.buf):
            raise DecodeError(
                f"{self.what}: {len(self.buf) - self.pos} trailing bytes after offset {self.pos}"
            )


def _check_fits(value: int, size: int, field: str) -> None:
    if not 0 <= value < 1 << (8 * size):
        raise ValueError(f"{field} out of range for u{8 * size}: {value}")


def _check_ids(items: list[bytes], field: str) -> None:
    if any(len(p) != ID_LEN for p in items):
        raise ValueError(f"{field} must be {ID_LEN} bytes each")


def _read_parents(r: _Reader) -> list[bytes]:
    count = r.uint(1, "parentsCount")
    return [r.take(ID_LEN, f"parent[{i}]") for i in range(count)]


def _read_options(r: _Reader) -> bytes:
    """Consume the options and return their raw bytes (count byte excluded)."""
    count = r.uint(1, "optionsCount")
    start = r.pos
    for i in range(count):
        otype = r.uint(1, f"option[{i}].type")
        if otype != OPT_PROTOCOL_PARAMS:
            raise DecodeError(f"milestone option[{i}]: unsupported option type {otype}")
        r.take(5, f"option[{i}].header")
        plen = r.uint(2, f"option[{i}].paramsLength")
        r.take(plen, f"option[{i}].params")
    return r.buf[start : r.pos]


def _count_options(options: bytes) -> int:
    n, pos = 0, 0
    while pos < len(options):
        if options[pos] != OPT_PROTOCOL_PARAMS or pos + _OPT_HEADER > len(options):
            raise ValueError("malformed milestone options")
        pos += _OPT_HEADER + int.from_bytes(options[pos + 6 : pos + 8], "little")
        n += 1
    if pos != len(options):
        raise ValueError("malformed milestone options")
    return n


def _read_essence(r: _Reader) -> tuple[MilestoneEssence, bytes]:
    begin = r.pos
    index = r.uint(4, "index")
    timestamp = r.uint(4, "timestamp")
    pv = r.uint(1, "protocolVersion")
    prev = r.take(ID_LEN, "previousMilestoneId")
    parents = _read_parents(r)
    inclusion = r.take(32, "inclusionMerkleRoot")
    applied = r.take(32, "appliedMerkleRoot")
    metadata = r.take(r.uint(2, "metadataLength"), "metadata")
    options = _read_options(r)
    essence = MilestoneEssence(
        index, timestamp, pv, prev, parents, inclusion, applied, metadata, options
    )
    return essence, r.buf[begin : r.pos]


def serialize_milestone_essence(e: MilestoneEssence) -> bytes:
    """Essence bytes as signed/hashed: no payload type word."""
    _check_ids([e.previous_milestone_id, e.inclusion_merkle_root, e.applied_merkle_root], "roots")
    _check_ids(e.parents, "parents")
    _check_fits(e.index, 4, "index")
    _check_fits(e.timestamp, 4, "timestamp")
    _check_fits(e.protocol_version, 1, "protocol_version")
    _check_fits(len(e.parents), 1, "parentsCount")
    _check_fits(len(e.metadata), 2, "metadataLength")
    n_opts = _count_options(e.options)
    _check_fits(n_opts, 1, "optionsCount")
    return b"".join(
        [
            e.index.to_bytes(4, "little"),
            e.timestamp.to_bytes(4, "little"),
            bytes([e.protocol_version]),
            e.previous_milestone_id,
            bytes([len(e.parents)]),
            *e.parents,
            e.inclusion_merkle_root,
            e.applied_merkle_root,
            len(e.metadata).to_bytes(2, "little"),
            e.metadata,
            bytes([n_opts]),
            e.options,
        ]
    )


def milestone_id(essence_bytes: bytes) -> bytes:
    """Milestone id: BLAKE2b-256 of the essence (payload type word excluded)."""
    return blake2b256(essence_bytes)


def _read_milestone(r: _Reader) -> MilestonePayload:
    essence, essence_bytes = _read_essence(r)
    sigs = []
    for i in range(r.uint(1, "signaturesCount")):
        stype = r.uint(1, f"signature[{i}].type")
        if stype != SIG_ED25519:
            raise DecodeError(f"milestone signature[{i}]: unsupported type {stype}")
        pk = r.take(PUBKEY_LEN, f"signature[{i}].publicKey")
        sig = r.take(SIG_LEN, f"signature[{i}].signature")
        sigs.append(Ed25519Sig(pk, sig))
    return MilestonePayload(essence, essence_bytes, sigs)


def parse_milestone_payload(raw_payload: bytes) -> MilestonePayload:
    """Parse a milestone payload including its leading u32 type word."""
    r = _Reader(raw_payload, "milestone payload")
    ptype = r.uint(4, "payload type")
    if ptype != PAYLOAD_MILESTONE:
        raise DecodeError(f"milestone payload: expected type 7, got {ptype}")
    out = _read_milestone(r)
    r.finish()
    return out


def _parse_payload(raw: bytes) -> TaggedData | MilestonePayload | OtherPayload:
    r = _Reader(raw, "payload")
    ptype = r.uint(4, "payload type")
    if ptype == PAYLOAD_TAGGED_DATA:
        tag = r.take(r.uint(1, "tagLength"), "tag")
        data = r.take(r.uint(4, "dataLength"), "data")
        r.finish()
        return TaggedData(tag, data)
    if ptype == PAYLOAD_MILESTONE:
        out = _read_milestone(r)
        r.finish()
        return out
    return OtherPayload(ptype, raw)


def parse_block(raw: bytes) -> Block:
    r = _Reader(raw, "block")
    pv = r.uint(1, "protocolVersion")
    parents = _read_parents(r)
    plen = r.uint(4, "payloadLength")
    payload = _parse_payload(r.take(plen, "payload")) if plen else None
    nonce = r.uint(8, "nonce")
    r.finish()
    return Block(pv, parents, payload, nonce)


def block_id(raw: bytes) -> bytes:
    return blake2b256(raw)


def serialize_tagged_block(
    parents: list[bytes],
    tag: bytes,
    data: bytes,
    nonce: int = 0,
    protocol_version: int = 2,
) -> bytes:
    _check_ids(parents, "parents")
    _check_fits(protocol_version, 1, "protocol_version")
    _check_fits(len(parents), 1, "parentsCount")
    _check_fits(len(tag), 1, "tagLength")
    _check_fits(len(data), 4, "dataLength")
    _check_fits(nonce, 8, "nonce")
    payload = (
        PAYLOAD_TAGGED_DATA.to_bytes(4, "little")
        + bytes([len(tag)])
        + tag
        + len(data).to_bytes(4, "little")
        + data
    )
    return b"".join(
        [
            bytes([protocol_version, len(parents)]),
            *parents,
            len(payload).to_bytes(4, "little"),
            payload,
            nonce.to_bytes(8, "little"),
        ]
    )
