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
# Milestone option types (TIP-29 / TIP-34).
OPT_RECEIPT = 0
OPT_PROTOCOL_PARAMS = 1
# Treasury Transaction payload type (TIP-34), carried inside a receipt.
PAYLOAD_TREASURY_TRANSACTION = 4
TREASURY_INPUT_TYPE = 1
TREASURY_OUTPUT_TYPE = 2
ED25519_ADDRESS_TYPE = 0
TAIL_TX_HASH_LEN = 49


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


def _scan_option(r: _Reader, i: int) -> None:
    """Advance past one milestone option, validating its layout."""
    name = f"option[{i}]"
    otype = r.uint(1, f"{name}.type")
    if otype == OPT_PROTOCOL_PARAMS:
        r.take(4 + 1, f"{name}.targetMilestoneIndex/protocolVersion")
        r.take(r.uint(2, f"{name}.paramsLength"), f"{name}.params")
    elif otype == OPT_RECEIPT:
        r.take(4 + 1, f"{name}.migratedAt/final")
        for j in range(r.uint(2, f"{name}.fundsCount")):
            r.take(TAIL_TX_HASH_LEN, f"{name}.funds[{j}].tailTransactionHash")
            atype = r.uint(1, f"{name}.funds[{j}].addressType")
            if atype != ED25519_ADDRESS_TYPE:
                raise DecodeError(f"milestone {name}.funds[{j}]: unsupported address type {atype}")
            r.take(32 + 8, f"{name}.funds[{j}].pubKeyHash/deposit")
        ptype = r.uint(4, f"{name}.treasury.payloadType")
        if ptype != PAYLOAD_TREASURY_TRANSACTION:
            raise DecodeError(f"milestone {name}: expected treasury transaction, got {ptype}")
        if r.uint(1, f"{name}.treasury.inputType") != TREASURY_INPUT_TYPE:
            raise DecodeError(f"milestone {name}: bad treasury input type")
        r.take(32, f"{name}.treasury.milestoneId")
        if r.uint(1, f"{name}.treasury.outputType") != TREASURY_OUTPUT_TYPE:
            raise DecodeError(f"milestone {name}: bad treasury output type")
        r.take(8, f"{name}.treasury.amount")
    else:
        raise DecodeError(f"milestone {name}: unsupported option type {otype}")


def _read_options(r: _Reader) -> bytes:
    """Consume the options and return their raw bytes (count byte excluded)."""
    count = r.uint(1, "optionsCount")
    start = r.pos
    for i in range(count):
        _scan_option(r, i)
    return r.buf[start : r.pos]


def _count_options(options: bytes) -> int:
    r = _Reader(options, "milestone options")
    n = 0
    while r.pos < len(options):
        _scan_option(r, n)
        n += 1
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
