"""The anchor service (TypeScript) held to the Python reference.

- vectors/witness_anchor.json: witness.anchor mirrors sealed by the anchor's MirrorSigner;
- anchor/test/vectors/checkpoint.json: checkpoints and policy hashes the anchor reproduces.

If either side drifts, these fail. Regenerate with the scripts named in each file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from witness_core import canon, checkpoint, envelope, policy, schema, verdicts
from witness_core.envelope import KeyInfo
from witness_core.ids import from_hex, to_hex

ANCHOR_VECTORS = Path(__file__).resolve().parents[2] / "anchor" / "test" / "vectors" / "checkpoint.json"


@pytest.fixture(scope="module")
def mirrors(vectors) -> dict:
    return vectors("witness_anchor")


def test_anchor_mirrors_verify_as_producer_signed(mirrors):
    key = KeyInfo(mirrors["kid"], from_hex(mirrors["publicKeyHex"]), None, None)
    assert len(mirrors["messages"]) >= 2
    prev = None
    for i, m in enumerate(mirrors["messages"], start=1):
        env = m["envelope"]
        chk = envelope.verify(env, mirrors["tag"], lambda kid: key if kid == key.kid else None)
        assert chk.verdict == verdicts.PRODUCER_SIGNED, chk.reason
        assert (chk.iss, chk.kid, chk.seq) == (mirrors["kid"].split("#")[0], mirrors["kid"], i)
        assert env["body"]["seq"] == i
        assert chk.prev == prev
        prev = "0x" + f"{i:02x}" * 32
        # The bytes the relay would post are the envelope's JCS, identical on both sides.
        assert canon.jcs(env) == m["data"].encode("utf-8")


def test_anchor_mirrors_pass_the_witness_anchor_schema(mirrors):
    for m in mirrors["messages"]:
        c = schema.classify(mirrors["tag"], m["data"].encode("utf-8"))
        assert (c.kind, c.schema_ok) == ("witness.anchor", True)
        assert c.json == m["envelope"]["body"]
        body = c.json
        assert body["checkpointHash"] == to_hex(checkpoint.hash(body["checkpoint"]))


def test_a_tampered_mirror_fails(mirrors):
    key = KeyInfo(mirrors["kid"], from_hex(mirrors["publicKeyHex"]), None, None)
    env = json.loads(mirrors["messages"][0]["data"])
    env["body"]["rebased"]["record"] += 1
    chk = envelope.verify(env, mirrors["tag"], lambda kid: key)
    assert chk.verdict == verdicts.FORGED


def test_anchor_checkpoint_vectors_match_the_reference():
    v = json.loads(ANCHOR_VECTORS.read_text(encoding="utf-8"))
    assert len(v["policies"]) >= 2 and len(v["checkpoints"]) >= 3
    for p in v["policies"]:
        loaded = policy.load(p["input"])
        assert policy.to_dict(loaded) == p["normalized"]
        assert to_hex(policy.policy_hash(loaded)) == p["hash"]
    for c in v["checkpoints"]:
        i = c["input"]
        ids = [from_hex(h) for h in i["milestoneIds"]]
        cp = checkpoint.build(
            i["network"], i["domain"], (i["first"], ids[0]), (i["first"] + len(ids) - 1, ids[-1]),
            ids, i["msgCount"], from_hex(i["policyHash"]),
            None if i["prevHash"] is None else from_hex(i["prevHash"]))
        assert cp == c["checkpoint"]
        assert canon.jcs(cp).decode("utf-8") == c["jcs"]
        assert to_hex(checkpoint.hash(cp)) == c["hash"]
        assert checkpoint.shape_error(c["checkpoint"]) is None
