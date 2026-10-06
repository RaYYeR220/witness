"""Test data: real milestones, cones and blocks captured from the local Tangle, plus synthetic
signed messages written straight into the store."""

from __future__ import annotations

import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_core import canon, codec, envelope, schema, verdicts
from witness_core.ids import blake2b256, from_hex
from witness_indexer.store import MessageRow

ISS = "did:iota:testnet:0x" + "5e" * 32
KID = ISS + "#sig-1"
SIGNER = Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)
SIGNER_PUBLIC = SIGNER.public_key().public_bytes_raw()


def _row(block_id: bytes, tag: str, data: bytes, *, ms_index: int | None, wf_index: int | None,
         ts: int, verdict: str | None = None, **extra) -> MessageRow:
    c = schema.classify(tag, data)
    kind = c.kind if (c.envelope is not None or isinstance(c.json, dict)) else schema.UNKNOWN
    if verdict is None:
        verdict = verdicts.UNSIGNED_LEGACY
        if kind == schema.UNKNOWN and tag in schema.KINDS:
            verdict = verdicts.MALFORMED
    canon_hash = canon.canon_hash(c.json) if c.json is not None else None
    return MessageRow(block_id=block_id, tag=tag, kind=kind, data=data, json=c.json,
                      ie_id=c.ie_id, canon_hash=canon_hash, verdict=verdict,
                      ms_index=ms_index, wf_index=wf_index, ts=ts, nonce=c.nonce, **extra)


async def seed_chain(store, vectors) -> dict:
    """Milestones 370..373 with their full cones and every captured tagged message.

    Returns {block id hex: milestone index} for the tagged messages."""
    blocks = {b["blockId"]: b for b in vectors("blocks")}
    ts = {}
    for m in vectors("milestones"):
        ts[m["index"]] = m["timestamp"]
        await store.put_milestone(
            m["index"], from_hex(m["milestoneId"]), m["timestamp"], from_hex(m["essence"]),
            [{"pk": s["pk"], "sig": s["sig"]} for s in m["signatures"]],
            from_hex(m["inclusionMerkleRoot"]), from_hex(m["previousMilestoneId"]))
    tagged = {}
    for cone in vectors("cones"):
        idx = cone["index"]
        for wf, bid_hex in enumerate(cone["blockIdsWhiteFlagOrder"]):
            b = blocks.get(bid_hex)
            bid = from_hex(bid_hex)
            if b is None:  # not captured: only its id matters for the Merkle tree
                await store.put_block(bid, idx, wf, b"\x00", -1)
                continue
            raw = from_hex(b["raw"])
            ptype = codec.PAYLOAD_TAGGED_DATA if b["kind"] == "tagged" else codec.PAYLOAD_MILESTONE
            await store.put_block(bid, idx, wf, raw, ptype)
            if b["kind"] != "tagged":
                continue
            row = _row(bid, b["tag"], from_hex(b["data"]), ms_index=idx, wf_index=wf,
                       ts=ts[idx])
            await store.put_message(row)
            if row.kind == "trust.score" and row.ie_id:
                await store.put_ie_score(row.ie_id, idx, ts[idx], float(row.json["score"]),
                                         bid, row.verdict)
            tagged[bid_hex] = idx
    return tagged


def sealed_score(body: dict, *, seq: int, prev: str | None = None, corr: str | None = None,
                 tag: str = "trust.score", now_ms: int = 1_791_283_600_000) -> dict:
    return envelope.seal(tag, body, iss=ISS, kid=KID, sign_key=SIGNER, seq=seq,
                         att_mode="producer", now_ms=now_ms, nonce=os.urandom(16),
                         prev=prev, corr=corr)


def signed_block(env: dict) -> tuple[bytes, bytes, bytes]:
    """(raw block, block id, data) of a tagged block carrying `env`."""
    data = json.dumps(env).encode()
    raw = codec.serialize_tagged_block([b"\x33" * 32], env["tag"].encode(), data)
    return raw, blake2b256(raw), data


async def put_signed(store, env: dict, *, ms_index: int, ts: int, wf_index: int = 1,
                     verdict: str = verdicts.PRODUCER_SIGNED) -> bytes:
    """Store a signed message as the indexer would; returns its (synthetic) block id."""
    _, bid, data = signed_block(env)
    prev = from_hex(env["prev"]) if env.get("prev") else None
    row = _row(bid, env["tag"], data, ms_index=ms_index, wf_index=wf_index, ts=ts,
               verdict=verdict, iss=env["iss"], kid=env["kid"], seq=env["seq"],
               iat=env["iat"], prev=prev, corr=env.get("corr"))
    await store.put_message(row)
    if row.kind == "trust.score" and row.ie_id:
        await store.put_ie_score(row.ie_id, ms_index, ts, float(row.json["score"]), bid,
                                 verdict)
    return bid
