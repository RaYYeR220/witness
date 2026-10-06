import json

import pytest
from witness_core import codec, ids


def _raw(v):
    return ids.from_hex(v["raw"])


def test_block_id_matches_vectors(vectors):
    for v in vectors("blocks"):
        assert ids.to_hex(codec.block_id(_raw(v))) == v["blockId"]


def test_parse_tagged_data(vectors):
    v = next(x for x in vectors("blocks") if x["tag"] == "trust.score")
    blk = codec.parse_block(_raw(v))
    assert isinstance(blk.payload, codec.TaggedData)
    assert blk.payload.tag == b"trust.score"
    assert blk.payload.data == ids.from_hex(v["data"])
    assert {"score", "id"} <= set(json.loads(blk.payload.data))


def test_parse_all_tagged_vectors(vectors):
    for v in vectors("blocks"):
        if v["kind"] == "tagged":
            p = codec.parse_block(_raw(v)).payload
            assert p.tag == v["tag"].encode()
            assert p.data == ids.from_hex(v["data"])


def test_parse_milestone_block(vectors):
    ms = {m["index"]: m for m in vectors("milestones")}
    found = 0
    for v in vectors("blocks"):
        if v["kind"] != "milestone":
            continue
        p = codec.parse_block(_raw(v)).payload
        assert isinstance(p, codec.MilestonePayload)
        m = ms[p.essence.index]
        assert ids.to_hex(p.essence.inclusion_merkle_root) == m["inclusionMerkleRoot"]
        assert len(p.signatures) == len(m["signatures"])
        found += 1
    assert found >= 1


def test_milestone_id_roundtrip(vectors):
    for m in vectors("milestones"):
        essence = ids.from_hex(m["essence"])
        # essence excludes the payload type word; wrap it to build a payload
        sigs = b"".join(
            b"\x00" + ids.from_hex(s["pk"]) + ids.from_hex(s["sig"]) for s in m["signatures"]
        )
        payload = (7).to_bytes(4, "little") + essence + bytes([len(m["signatures"])]) + sigs
        p = codec.parse_milestone_payload(payload)
        assert p.essence.index == m["index"]
        assert p.essence.timestamp == m["timestamp"]
        assert ids.to_hex(p.essence.previous_milestone_id) == m["previousMilestoneId"]
        assert codec.serialize_milestone_essence(p.essence) == essence
        assert p.essence_bytes == essence
        assert ids.to_hex(codec.milestone_id(essence)) == m["milestoneId"]
        assert [ids.to_hex(s.public_key) for s in p.signatures] == [
            s["pk"] for s in m["signatures"]
        ]


def test_truncated_raises(vectors):
    for v in vectors("blocks")[:1] + vectors("blocks")[-1:] + vectors("blocks")[5:6]:
        with pytest.raises(codec.DecodeError):
            codec.parse_block(_raw(v)[:-1])


def test_every_prefix_raises_decode_error(vectors):
    raw = _raw(next(v for v in vectors("blocks") if v["kind"] == "milestone"))
    for n in range(len(raw)):
        with pytest.raises(codec.DecodeError):
            codec.parse_block(raw[:n])


def test_trailing_bytes_raise(vectors):
    for v in vectors("blocks")[:2]:
        with pytest.raises(codec.DecodeError):
            codec.parse_block(_raw(v) + b"\x00")


def test_decode_error_is_value_error():
    assert issubclass(codec.DecodeError, ValueError)


def test_serialize_tagged_block_roundtrip():
    parents = [b"\x11" * 32]
    raw = codec.serialize_tagged_block(parents, b"t", b"{}")
    blk = codec.parse_block(raw)
    assert blk.protocol_version == 2
    assert blk.parents == parents
    assert blk.payload == codec.TaggedData(tag=b"t", data=b"{}")
    assert blk.nonce == 0
    assert (
        codec.parse_block(codec.serialize_tagged_block(parents, b"t", b"{}", nonce=2**40)).nonce
        == 2**40
    )


def test_block_without_payload():
    raw = bytes([2, 1]) + b"\x22" * 32 + (0).to_bytes(4, "little") + bytes(8)
    blk = codec.parse_block(raw)
    assert blk.payload is None


def test_other_payload_kept_raw():
    payload = (6).to_bytes(4, "little") + b"abc"
    raw = bytes([2, 1]) + b"\x22" * 32 + len(payload).to_bytes(4, "little") + payload + bytes(8)
    blk = codec.parse_block(raw)
    assert blk.payload == codec.OtherPayload(type=6, raw=payload)


def test_from_hex_rejects():
    for bad in ("0xzz", "0x123"):
        with pytest.raises(ValueError):
            ids.from_hex(bad)


def test_hex_helpers():
    assert ids.to_hex(b"\xab\x01") == "0xab01"
    assert ids.from_hex("ab01") == ids.from_hex("0xab01") == b"\xab\x01"
    assert len(ids.blake2b256(b"")) == 32
