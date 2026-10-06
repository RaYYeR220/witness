"""Offline forgeries of proof bundles. Nothing in this module touches the network.

`forge_milestone_bundle` plays an attacker who knows the organisers' public sample
coordinator keys: it invents a tagged block and a milestone with the real milestone's
index, signs the milestone with those keys and packages the result as a proof bundle.
Block hash, inclusion and milestone signatures all check out; only the anchor record
on IOTA Rebased, which the attacker cannot rewrite, gives it away.

`tamper_bundle` produces the three cheaper attacks on a genuine bundle.
"""

from __future__ import annotations

import copy
import dataclasses
import random
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_core import bundle, checkpoint, codec, merkle
from witness_core.codec import Ed25519Sig
from witness_core.ids import from_hex, to_hex

TamperKind = Literal["byte_flip", "merkle_path", "checkpoint"]
TAMPER_KINDS: tuple[str, ...] = ("byte_flip", "merkle_path", "checkpoint")

FORGED_DATA = b'{"forged":true,"note":"block invented by the attacker"}'


def _essence_of(b: dict) -> codec.MilestoneEssence:
    raw = from_hex(b["milestone"]["essence"])
    wrapped = codec.PAYLOAD_MILESTONE.to_bytes(4, "little") + raw + b"\x00"
    return codec.parse_milestone_payload(wrapped).essence


def seed_of(private_key: bytes) -> bytes:
    """The 32-byte Ed25519 seed of a sample key (32-byte seed, or seed || public key)."""
    if len(private_key) not in (32, 64):
        raise ValueError("sample private keys are 32 bytes (seed) or 64 bytes (seed || public)")
    return private_key[:32]


def _data_region(raw: bytes) -> tuple[int, int]:
    """Byte range of the tagged-data `data` field inside a serialized block."""
    block = codec.parse_block(raw)
    payload = block.payload
    if not isinstance(payload, codec.TaggedData) or not payload.data:
        raise ValueError("block carries no tagged data to flip a byte in")
    start = 2 + 32 * len(block.parents) + 4 + 4 + 1 + len(payload.tag) + 4
    return start, start + len(payload.data)


def forge_milestone_bundle(real_bundle: dict, sample_private_keys: list[bytes]) -> dict:
    """Fake block + fake milestone for the index of `real_bundle`'s milestone.

    The fake milestone differs from the real one in its parents and inclusion root (it
    includes only the fake block) and is signed by every key in `sample_private_keys`.
    The anchor section of the real bundle is carried over unchanged, so the verifier's
    step 5 compares the forged milestone against the real checkpoint and fails.
    """
    if not sample_private_keys:
        raise ValueError("at least one sample private key is required")
    if not real_bundle.get("anchor"):
        raise ValueError("the real bundle needs an anchor section for step 5 to go red")
    real_block = codec.parse_block(from_hex(real_bundle["block"]["raw"]))
    tag = (
        real_block.payload.tag
        if isinstance(real_block.payload, codec.TaggedData)
        else b"forged"
    )
    fake_raw = codec.serialize_tagged_block(real_block.parents, tag, FORGED_DATA)
    fake_id = codec.block_id(fake_raw)

    real_essence = _essence_of(real_bundle)
    fake_essence = dataclasses.replace(
        real_essence,
        parents=[fake_id],
        inclusion_merkle_root=merkle.root([fake_id]),
    )
    essence_bytes = codec.serialize_milestone_essence(fake_essence)
    mid = codec.milestone_id(essence_bytes)
    sigs = []
    for key in sample_private_keys:
        priv = Ed25519PrivateKey.from_private_bytes(seed_of(key))
        sigs.append(Ed25519Sig(priv.public_key().public_bytes_raw(), priv.sign(mid)))
    return bundle.build(
        network=real_bundle["network"],
        block_raw=fake_raw,
        milestone_essence=essence_bytes,
        milestone_sigs=sigs,
        cone_ids=[fake_id],
        envelope_check=None,
        did_doc_snapshot=None,
        anchor=copy.deepcopy(real_bundle["anchor"]),
    )


def real_anchor_record(b: dict) -> dict:
    """The on-chain record a verifier would fetch for `b`, as far as the bundle's own
    (genuine) checkpoint is concerned. For tests and offline runs only."""
    cp = b["anchor"]["checkpoint"]
    return {"checkpoint": cp, "checkpointHash": to_hex(checkpoint.hash(cp))}


def tamper_bundle(
    b: dict, kind: TamperKind, rng: random.Random | None = None
) -> dict:
    """Copy of `b` with one attack applied.

    byte_flip    (A07) flips one bit inside the tagged-data payload of the raw block (the block
                 still parses), keeping the claimed id
    merkle_path  (A08) corrupts one step of the inclusion path (adds one if the path is empty)
    checkpoint   (A10) doctors the anchor checkpoint's msgCount; its membership proof
                 stays valid but its hash no longer equals the on-chain record
    """
    rng = rng or random.Random()
    out = copy.deepcopy(b)
    if kind == "byte_flip":
        raw = bytearray(from_hex(out["block"]["raw"]))
        lo, hi = _data_region(bytes(raw))
        raw[rng.randrange(lo, hi)] ^= 1 << rng.randrange(8)
        out["block"]["raw"] = to_hex(bytes(raw))
    elif kind == "merkle_path":
        path = out["inclusion"]["path"]
        if path:
            step = path[rng.randrange(len(path))]
            digest = bytearray(from_hex(step["hash"]))
            digest[rng.randrange(32)] ^= 0xFF
            step["hash"] = to_hex(bytes(digest))
        else:
            path.append({"side": "R", "hash": to_hex(rng.randbytes(32))})
    elif kind == "checkpoint":
        if not out.get("anchor"):
            raise ValueError("bundle has no anchor to doctor")
        out["anchor"]["checkpoint"]["msgCount"] += 1 + rng.randrange(5)
    else:
        raise ValueError(f"unknown tamper kind {kind!r}")
    return out
