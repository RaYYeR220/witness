"""Proof bundles from the store, and the node's JSON rendering of blocks and milestones for
the inx-poi proof format."""

from __future__ import annotations

from witness_core import bundle, checkpoint, codec, merkle, poi_compat
from witness_core.envelope import EnvelopeCheck
from witness_core.ids import from_hex, to_hex

from .store import ExplorerStore


class NoProof(LookupError):
    """The block is not part of an indexed milestone cone."""


class Unrenderable(ValueError):
    """The block or milestone uses a structure the inx-poi rendering does not cover."""


class Inconsistent(ValueError):
    """Stored chain data that contradicts itself, e.g. a raw block not hashing to its id."""


async def material(store: ExplorerStore, block_id: bytes) -> dict:
    """Raw block, its milestone and the milestone's full white-flag cone."""
    block = await store.block_row(block_id)
    if block is None:
        raise NoProof(f"block {to_hex(block_id)} is not in a milestone cone indexed by this "
                      "explorer (unknown, or not confirmed yet)")
    raw = bytes(block["raw"])
    if codec.block_id(raw) != block_id:
        raise Inconsistent(f"the stored bytes of block {to_hex(block_id)} do not hash to its "
                           "id; the explorer's database may have been altered")
    ms = await store.milestone(block["ms_index"])
    cone = [bytes(c) for c in await store.cone_ids(block["ms_index"])]
    if ms is None or block_id not in cone:
        raise NoProof(f"milestone {block['ms_index']} of block {to_hex(block_id)} is not "
                      "indexed")
    essence = bytes(ms["essence"])
    if merkle.root(cone) != _essence(essence).inclusion_merkle_root:
        raise Inconsistent(f"the indexed cone of milestone {block['ms_index']} does not "
                           "reproduce its inclusion Merkle root; the explorer's database may "
                           "have been altered")
    sigs = [codec.Ed25519Sig(from_hex(s["pk"]), from_hex(s["sig"])) for s in ms["sigs"]]
    return {"raw": raw, "ms_index": block["ms_index"], "essence": essence, "sigs": sigs,
            "cone": cone}


async def anchor_section(store: ExplorerStore, ms_index: int, *, trail_id: str | None,
                         rebased_network: str | None) -> dict | None:
    """The anchored checkpoint covering the milestone, with its membership path, if any."""
    if trail_id is None:
        return None  # a bundle can only name the trail the verifier is told to pin
    row = await store.anchor_covering(ms_index)
    if row is None or row["status"] != "anchored" or row["record"] is None:
        return None
    cp = row["checkpoint"]
    if checkpoint.shape_error(cp) is not None:
        return None
    frm, to = cp["from"]["index"], cp["to"]["index"]
    ids = await store.milestone_ids(frm, to)
    if len(ids) != to - frm + 1 or to_hex(merkle.root([bytes(i) for i in ids])) != cp["msRoot"]:
        return None  # the indexed milestones do not reproduce the anchored root
    return {
        "checkpoint": cp,
        "msPath": checkpoint.membership_path([bytes(i) for i in ids], ms_index - frm),
        "rebased": {"network": rebased_network or row["network"], "trail": trail_id,
                    "record": row["record"], "tx": row["tx"]},
    }


def build_bundle(network: str, mat: dict, message: dict | None, did_snapshot: dict | None,
                 anchor: dict | None) -> dict:
    check = None
    if message is not None and message.get("verdict") is not None:
        check = EnvelopeCheck(verdict=message["verdict"], iss=message.get("iss"),
                              kid=message.get("kid"), seq=message.get("seq"),
                              iat=message.get("iat"), reason=None)
    return bundle.build(network=network, block_raw=mat["raw"], milestone_essence=mat["essence"],
                        milestone_sigs=mat["sigs"], cone_ids=mat["cone"], envelope_check=check,
                        did_doc_snapshot=did_snapshot, anchor=anchor)


# -- inx-poi -----------------------------------------------------------------------------------

def _options_json(options: bytes) -> list[dict]:
    out = []
    pos = 0
    while pos < len(options):
        otype = options[pos]
        if otype != codec.OPT_PROTOCOL_PARAMS:
            raise Unrenderable("milestone carries a receipt option")
        target = int.from_bytes(options[pos + 1:pos + 5], "little")
        version = options[pos + 5]
        size = int.from_bytes(options[pos + 6:pos + 8], "little")
        params = options[pos + 8:pos + 8 + size]
        out.append({"type": codec.OPT_PROTOCOL_PARAMS, "targetMilestoneIndex": target,
                    "protocolVersion": version, "params": to_hex(params)})
        pos += 8 + size
    return out


def milestone_json(essence: codec.MilestoneEssence, sigs: list[codec.Ed25519Sig]) -> dict:
    """A milestone payload as the node's REST API renders it."""
    out: dict = {
        "type": codec.PAYLOAD_MILESTONE, "index": essence.index, "timestamp": essence.timestamp,
        "protocolVersion": essence.protocol_version,
        "previousMilestoneId": to_hex(essence.previous_milestone_id),
        "parents": [to_hex(p) for p in essence.parents],
        "inclusionMerkleRoot": to_hex(essence.inclusion_merkle_root),
        "appliedMerkleRoot": to_hex(essence.applied_merkle_root),
    }
    if essence.metadata:
        out["metadata"] = to_hex(essence.metadata)
    if essence.options:
        out["options"] = _options_json(essence.options)
    out["signatures"] = [{"type": codec.SIG_ED25519, "publicKey": to_hex(s.public_key),
                          "signature": to_hex(s.signature)} for s in sigs]
    return out


def block_json(raw: bytes) -> dict:
    """A block as the node's REST API renders it (tagged data and milestone payloads)."""
    try:
        block = codec.parse_block(raw)
    except codec.DecodeError as e:
        raise Unrenderable(f"block does not parse: {e}") from None
    out: dict = {"protocolVersion": block.protocol_version,
                 "parents": [to_hex(p) for p in block.parents]}
    payload = block.payload
    if isinstance(payload, codec.TaggedData):
        out["payload"] = {"type": codec.PAYLOAD_TAGGED_DATA, "tag": to_hex(payload.tag),
                          "data": to_hex(payload.data)}
    elif isinstance(payload, codec.MilestonePayload):
        out["payload"] = milestone_json(payload.essence, payload.signatures)
    elif payload is not None:
        raise Unrenderable(f"payload type {payload.type} is not rendered for inx-poi")
    out["nonce"] = str(block.nonce)
    return out


def _essence(essence_bytes: bytes) -> codec.MilestoneEssence:
    """Decode bare essence bytes (as signed) by wrapping them in a signature-less payload."""
    wrapped = codec.PAYLOAD_MILESTONE.to_bytes(4, "little") + essence_bytes + b"\x00"
    return codec.parse_milestone_payload(wrapped).essence


def inx_poi(mat: dict) -> dict:
    """The proof in the shape inx-poi's `/api/poi/v1/create` returns (and `/validate` takes)."""
    bid = codec.block_id(mat["raw"])
    essence = _essence(mat["essence"])
    return {"milestone": milestone_json(essence, mat["sigs"]), "block": block_json(mat["raw"]),
            "proof": poi_compat.to_inx_poi(mat["cone"], mat["cone"].index(bid))}
