import copy
import dataclasses
import json
import os
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st
from witness_core import bundle, canon, checkpoint, codec, envelope, merkle, verdicts
from witness_core.bundle import Ladder, VerifierConfig
from witness_core.codec import Ed25519Sig, MilestoneEssence
from witness_core.envelope import EnvelopeCheck
from witness_core.ids import blake2b256, from_hex, to_hex

VECTORS = Path(__file__).parent / "vectors" / "bundles.json"
NETWORK = "private_tangle1"
DID = "did:iota:testnet:0x5e1f"
KID = DID + "#sig-1"
NOW_MS = 1_791_283_590_000
TRAIL = "0x" + "7a" * 32
REBASED = {"network": "testnet", "trail": TRAIL, "record": 3, "tx": "5xGp7rWq2Tz9"}
REAL_BLOCK = "0x972a878cf06f2cf6b7d4a1443dbb5f12fdda376fa7537a82dad8e7257a477967"
STEPS = ["block_hash", "inclusion", "milestone_signatures", "envelope", "anchor"]

SIGNER = Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)
KEX = X25519PrivateKey.from_private_bytes(b"\x06" * 32)
ATTACKERS = [Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32) for n in (0x0A, 0x0B)]
ATTACKER_PUBS = {k.public_key().public_bytes_raw() for k in ATTACKERS}
# The identity point as a public key: OpenSSL accepts R = identity, S = 0 under it for any
# message, so it must never verify anything.
IDENTITY = (1).to_bytes(32, "little")
IDENTITY_SIG = IDENTITY + bytes(32)


# ---------------------------------------------------------------- helpers


def _coordinators(vectors) -> list[Ed25519PrivateKey]:
    keys = vectors("coordinator_keys")["privateKeys"]
    return [Ed25519PrivateKey.from_private_bytes(from_hex(k)[:32]) for k in keys]


def _cfg(vectors, **kw) -> VerifierConfig:
    base: dict[str, Any] = {
        "network": NETWORK,
        "trusted_coordinator_keys": {
            from_hex(k) for k in vectors("coordinator_keys")["publicKeys"]
        },
        "threshold": 2,
        "rebased_network": "testnet",
        "trail_id": TRAIL,
    }
    base.update(kw)
    return VerifierConfig(**base)


def _ok(ladder: Ladder) -> str:
    """Compact ladder signature: T / F / N per step, then the overall verdict."""
    marks = "".join({True: "T", False: "F", None: "N"}[s.ok] for s in ladder.steps)
    return f"{marks} {ladder.overall}"


def _step(ladder: Ladder, name: str) -> bundle.StepResult:
    return next(s for s in ladder.steps if s.name == name)


def _real_bundle(vectors, block_id: str = REAL_BLOCK) -> dict:
    raw = next(b["raw"] for b in vectors("blocks") if b["blockId"] == block_id)
    for ms, cone in zip(vectors("milestones"), vectors("cones"), strict=True):
        if block_id in cone["blockIdsWhiteFlagOrder"]:
            return bundle.build(
                network=NETWORK,
                block_raw=from_hex(raw),
                milestone_essence=from_hex(ms["essence"]),
                milestone_sigs=[
                    Ed25519Sig(from_hex(s["pk"]), from_hex(s["sig"])) for s in ms["signatures"]
                ],
                cone_ids=[from_hex(i) for i in cone["blockIdsWhiteFlagOrder"]],
                envelope_check=None,
                did_doc_snapshot=None,
                anchor=None,
            )
    raise AssertionError(f"{block_id} not in any cone")


def _snapshot(
    revoked_at_ms: int | None = None, signer: Ed25519PrivateKey = SIGNER
) -> dict:
    """DID document in the anchor service's resolve shape."""
    return {
        "doc": {"id": DID},
        "version": "4",
        "keys": [
            {
                "kid": KID,
                "type": "Ed25519",
                "publicKeyHex": to_hex(signer.public_key().public_bytes_raw()),
                "revokedAtMs": revoked_at_ms,
            },
            {
                "kid": DID + "#kex-1",
                "type": "X25519",
                "publicKeyHex": to_hex(KEX.public_key().public_bytes_raw()),
                "revokedAtMs": None,
            },
        ],
    }


def _envelope(**kw) -> dict:
    args: dict[str, Any] = {
        "iss": DID,
        "kid": KID,
        "sign_key": SIGNER,
        "seq": 1,
        "att_mode": "producer",
        "now_ms": NOW_MS,
        "nonce": bytes(range(16)),
        "corr": "incident-7",
    }
    args.update(kw)
    return envelope.seal("trust.score", {"score": 0.82, "id": "MyDomain:fa163e5e25ef"}, **args)


@dataclasses.dataclass
class Synthetic:
    bundle: dict
    record: dict
    checkpoint: dict
    window: list[bytes]
    milestone_id: bytes


def _synthetic(
    vectors,
    env: dict,
    *,
    snapshot: dict | None = None,
    claimed: EnvelopeCheck | None = None,
    window_override: list[bytes] | None = None,
) -> Synthetic:
    """A tagged block carrying `env`, confirmed by a coordinator-signed milestone 374.

    Offline only: the milestone is signed with the published test coordinator keys and
    never leaves the test.
    """
    milestones = vectors("milestones")
    last = milestones[-1]
    in_cones = {i for c in vectors("cones") for i in c["blockIdsWhiteFlagOrder"]}
    # Milestone 373's own block is not referenced yet: it opens the cone of 374.
    ms373_block = from_hex(
        next(
            b["blockId"]
            for b in vectors("blocks")
            if b["kind"] == "milestone" and b["blockId"] not in in_cones
        )
    )
    tip = from_hex(vectors("cones")[-1]["blockIdsWhiteFlagOrder"][-1])
    raw = codec.serialize_tagged_block(sorted([ms373_block, tip]), b"trust.score", canon.jcs(env))
    bid = codec.block_id(raw)
    cone = [ms373_block, bid]
    essence = MilestoneEssence(
        index=last["index"] + 1,
        timestamp=last["timestamp"] + 5,
        protocol_version=2,
        previous_milestone_id=from_hex(last["milestoneId"]),
        parents=[bid],
        inclusion_merkle_root=merkle.root(cone),
        applied_merkle_root=merkle.root([]),
        metadata=b"",
        options=b"",
    )
    essence_bytes = codec.serialize_milestone_essence(essence)
    mid = codec.milestone_id(essence_bytes)
    sigs = [
        Ed25519Sig(k.public_key().public_bytes_raw(), k.sign(mid)) for k in _coordinators(vectors)
    ]
    window = [from_hex(m["milestoneId"]) for m in milestones] + [mid]
    if window_override is not None:
        window = window_override
    first = last["index"] + 2 - len(window)
    cp = checkpoint.build(
        NETWORK,
        "MyDomain",
        (first, window[0]),
        (first + len(window) - 1, window[-1]),
        window,
        11,
        blake2b256(b"writer policy v1"),
        None,
    )
    pos = window.index(mid) if mid in window else len(window) - 1
    anchor = {
        "checkpoint": cp,
        "msPath": checkpoint.membership_path(window, pos),
        "rebased": dict(REBASED),
    }
    snap = _snapshot() if snapshot is None else snapshot
    if claimed is None:
        claimed = envelope.verify(env, "trust.score", bundle.snapshot_resolver(snap))
    b = bundle.build(
        network=NETWORK,
        block_raw=raw,
        milestone_essence=essence_bytes,
        milestone_sigs=sigs,
        cone_ids=cone,
        envelope_check=claimed,
        did_doc_snapshot=snap,
        anchor=anchor,
    )
    return Synthetic(b, {"checkpointHash": to_hex(checkpoint.hash(cp))}, cp, window, mid)


def _flip_hex(h: str, byte_index: int = 0) -> str:
    raw = bytearray(from_hex(h))
    raw[byte_index] ^= 0x01
    return to_hex(bytes(raw))


def _flip_raw(b: dict) -> dict:
    out = copy.deepcopy(b)
    out["block"]["raw"] = _flip_hex(out["block"]["raw"], -1)  # last nonce byte: still parses
    return out


def _corrupt_path(b: dict) -> dict:
    out = copy.deepcopy(b)
    out["inclusion"]["path"][0]["hash"] = _flip_hex(out["inclusion"]["path"][0]["hash"])
    return out


def _corrupt_sig(b: dict) -> dict:
    out = copy.deepcopy(b)
    out["milestone"]["signatures"][0]["sig"] = _flip_hex(out["milestone"]["signatures"][0]["sig"])
    return out


def _drop_sig(b: dict) -> dict:
    out = copy.deepcopy(b)
    out["milestone"]["signatures"] = out["milestone"]["signatures"][1:]
    return out


def _set(b: dict, path: tuple, value: Any) -> dict:
    target = b
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return b


def _fetch(record: Any):
    return lambda anchor: copy.deepcopy(record)


def _registry(doc: dict | None = None):
    """Trusted DID resolver serving the issuer's real document."""
    docs = {DID: _snapshot() if doc is None else doc}
    return lambda did: copy.deepcopy(docs.get(did))


def _boom(*_args):
    raise OSError("registry unreachable")


@pytest.fixture(scope="module")
def syn(vectors) -> Synthetic:
    return _synthetic(vectors, _envelope())


# ---------------------------------------------------------------- build


def test_build_shape(vectors):
    b = _real_bundle(vectors)
    ms = vectors("milestones")[0]
    cone = vectors("cones")[0]["blockIdsWhiteFlagOrder"]
    assert b["v"] == 1
    assert b["network"] == NETWORK
    assert b["block"]["id"] == REAL_BLOCK
    assert from_hex(b["block"]["id"]) == blake2b256(from_hex(b["block"]["raw"]))
    assert b["milestone"]["index"] == 370
    assert b["milestone"]["id"] == ms["milestoneId"]
    assert b["milestone"]["essence"] == ms["essence"]
    assert b["milestone"]["signatures"] == ms["signatures"]
    assert b["inclusion"]["leafIndex"] == cone.index(REAL_BLOCK)
    assert b["inclusion"]["leafCount"] == len(cone)
    steps = [merkle.PathStep(s["side"], from_hex(s["hash"])) for s in b["inclusion"]["path"]]
    assert merkle.verify(from_hex(REAL_BLOCK), steps, from_hex(ms["inclusionMerkleRoot"]))
    assert b["envelope"] is None
    assert b["anchor"] is None
    assert json.loads(json.dumps(b)) == b


def test_build_envelope_and_anchor_sections(syn):
    b = syn.bundle
    assert b["envelope"]["verdict"] == verdicts.PRODUCER_SIGNED
    assert b["envelope"]["didDoc"] == _snapshot()
    assert b["envelope"]["didVersion"] == "4"
    assert b["anchor"]["checkpoint"] == syn.checkpoint
    assert b["anchor"]["rebased"] == REBASED
    assert all(set(s) == {"side", "hash"} for s in b["anchor"]["msPath"])
    assert json.loads(json.dumps(b)) == b


def test_build_rejects_block_outside_cone(vectors):
    ms = vectors("milestones")[0]
    other = next(b for b in vectors("blocks") if b["blockId"] not in
                 vectors("cones")[0]["blockIdsWhiteFlagOrder"])
    with pytest.raises(ValueError):
        bundle.build(
            network=NETWORK,
            block_raw=from_hex(other["raw"]),
            milestone_essence=from_hex(ms["essence"]),
            milestone_sigs=[],
            cone_ids=[from_hex(i) for i in vectors("cones")[0]["blockIdsWhiteFlagOrder"]],
            envelope_check=None,
            did_doc_snapshot=None,
            anchor=None,
        )


# ---------------------------------------------------------------- steps 1-3 on real data


def test_bundle_valid_from_vectors(vectors):
    cfg = _cfg(vectors)
    raws = {b["blockId"]: b for b in vectors("blocks")}
    checked = 0
    for cone in vectors("cones"):
        for bid in cone["blockIdsWhiteFlagOrder"]:
            if bid not in raws:
                continue
            ladder = bundle.verify(_real_bundle(vectors, bid), cfg)
            assert [s.name for s in ladder.steps] == STEPS
            assert _ok(ladder) == "TTTNN PARTIAL", (bid, ladder)
            detail = _step(ladder, "envelope").detail
            if raws[bid]["kind"] == "tagged":
                assert detail == "unsigned legacy message"
            else:
                assert detail == "block carries no tagged data"
            checked += 1
    assert checked == 13


@pytest.mark.parametrize(
    "name,mutate,cfg_kw",
    [
        ("block_hash", _flip_raw, {}),
        ("inclusion", _corrupt_path, {}),
        ("milestone_signatures", _corrupt_sig, {}),
        ("milestone_signatures", lambda b: b, {"trusted_coordinator_keys": ATTACKER_PUBS}),
    ],
)
def test_bundle_each_step_negative_control(vectors, name, mutate, cfg_kw):
    base = _real_bundle(vectors)
    before = bundle.verify(base, _cfg(vectors))
    after = bundle.verify(mutate(base), _cfg(vectors, **cfg_kw))
    assert after.overall == "INVALID"
    for b_step, a_step in zip(before.steps, after.steps, strict=True):
        if a_step.name == name:
            assert b_step.ok is True and a_step.ok is False, a_step
        else:
            assert a_step.ok == b_step.ok, a_step


def test_threshold(vectors):
    base = _real_bundle(vectors)
    one = _drop_sig(base)
    assert _step(bundle.verify(one, _cfg(vectors)), "milestone_signatures").ok is False
    assert _step(bundle.verify(one, _cfg(vectors, threshold=1)), "milestone_signatures").ok is True
    # The same key twice counts once.
    dup = copy.deepcopy(one)
    dup["milestone"]["signatures"] *= 2
    assert _step(bundle.verify(dup, _cfg(vectors)), "milestone_signatures").ok is False
    # A pinned threshold below one is a configuration error, never a free pass.
    for t in (0, -1, 3):
        ladder = bundle.verify(base, _cfg(vectors, threshold=t))
        assert _step(ladder, "milestone_signatures").ok is False, t


def test_forged_milestone_signed_by_attacker(vectors):
    b = _real_bundle(vectors)
    mid = from_hex(b["milestone"]["id"])
    b["milestone"]["signatures"] = [
        {"pk": to_hex(k.public_key().public_bytes_raw()), "sig": to_hex(k.sign(mid))}
        for k in ATTACKERS
    ]
    assert _ok(bundle.verify(b, _cfg(vectors))) == "TTFNN INVALID"
    assert _ok(bundle.verify(b, _cfg(vectors, trusted_coordinator_keys=ATTACKER_PUBS))) == (
        "TTTNN PARTIAL"
    )


def _weak_coordinator(b: dict) -> dict:
    """One real coordinator signature plus an identity-key signature that OpenSSL accepts."""
    out = copy.deepcopy(b)
    out["milestone"]["signatures"] = [
        out["milestone"]["signatures"][0],
        {"pk": to_hex(IDENTITY), "sig": to_hex(IDENTITY_SIG)},
    ]
    return out


def test_small_order_coordinator_key_is_never_counted(vectors):
    """Pinning a weak key by mistake must not let anyone sign milestones with it."""
    b = _weak_coordinator(_real_bundle(vectors))
    pinned = {from_hex(k) for k in vectors("coordinator_keys")["publicKeys"]} | {IDENTITY}
    step = _step(bundle.verify(b, _cfg(vectors, trusted_coordinator_keys=pinned)),
                 "milestone_signatures")
    assert step.ok is False and "1 valid signature(s)" in step.detail
    only_weak = _cfg(vectors, trusted_coordinator_keys={IDENTITY}, threshold=1)
    assert _step(bundle.verify(b, only_weak), "milestone_signatures").ok is False


def _weak_signer_snapshot() -> dict:
    snap = _snapshot()
    snap["keys"][0]["publicKeyHex"] = to_hex(IDENTITY)
    return snap


def _weak_signed() -> dict:
    return {**_envelope(), "sig": envelope._b64(IDENTITY_SIG)}


def test_small_order_signer_key_is_forged(vectors):
    weak = _weak_signer_snapshot()
    claimed = EnvelopeCheck(verdicts.PRODUCER_SIGNED, DID, KID, 1, NOW_MS, None)
    s = _synthetic(vectors, _weak_signed(), snapshot=weak, claimed=claimed)
    step = _step(bundle.verify(s.bundle, _cfg(vectors), resolve_did=_registry(weak)), "envelope")
    assert (step.ok, step.detail) == (False, "FORGED: weak public key")


def test_milestone_claims_must_match_essence(vectors):
    b = _real_bundle(vectors)
    wrong_id = copy.deepcopy(b)
    wrong_id["milestone"]["id"] = _flip_hex(b["milestone"]["id"])
    assert _step(bundle.verify(wrong_id, _cfg(vectors)), "milestone_signatures").ok is False
    wrong_index = copy.deepcopy(b)
    wrong_index["milestone"]["index"] = 999
    assert _step(bundle.verify(wrong_index, _cfg(vectors)), "milestone_signatures").ok is False


def test_essence_tamper_breaks_signatures_and_root(vectors):
    b = _real_bundle(vectors)
    b["milestone"]["essence"] = _flip_hex(b["milestone"]["essence"], 100)  # inside a parent id
    ladder = bundle.verify(b, _cfg(vectors))
    assert _step(ladder, "milestone_signatures").ok is False
    assert ladder.overall == "INVALID"


def _with_fake_root(b: dict) -> dict:
    """Point the inclusion path at a root of our choosing and claim that root in the bundle."""
    out = copy.deepcopy(b)
    bid = from_hex(out["block"]["id"])
    fake_cone = [bid, b"\x99" * 32]
    fake_root = to_hex(merkle.root(fake_cone))
    out["inclusion"]["path"] = [
        {"side": s.side, "hash": to_hex(s.hash)} for s in merkle.audit_path(fake_cone, 0)
    ]
    out["inclusion"]["root"] = fake_root
    out["inclusion"]["inclusionMerkleRoot"] = fake_root
    out["milestone"]["inclusionMerkleRoot"] = fake_root
    return out


def test_root_comes_from_essence_not_bundle(vectors):
    """A bundle-supplied root (and a path to it) must not satisfy step 2."""
    b = _with_fake_root(_real_bundle(vectors))
    assert _step(bundle.verify(b, _cfg(vectors)), "inclusion").ok is False


def test_bundle_network_must_be_pinned(vectors):
    """Coordinator keys are pinned per network, so a foreign network label fails step 3."""
    ladder = bundle.verify(_real_bundle(vectors), _cfg(vectors, network="another_tangle"))
    assert _ok(ladder) == "TTFNN INVALID"
    assert "network" in _step(ladder, "milestone_signatures").detail
    b = _real_bundle(vectors)
    b["network"] = "another_tangle"
    assert _ok(bundle.verify(b, _cfg(vectors))) == "TTFNN INVALID"


@pytest.mark.parametrize(
    "where,mutate,expect",
    [
        ("raw upper", lambda b: _set(b, ("block", "raw"), b["block"]["raw"].upper()), "F"),
        ("raw no 0x", lambda b: _set(b, ("block", "raw"), b["block"]["raw"][2:]), "F"),
        ("id upper", lambda b: _set(b, ("block", "id"), "0x" + b["block"]["id"][2:].upper()),
         "FF"),
        ("path no 0x", lambda b: _set(b, ("inclusion", "path", 0, "hash"),
                                      b["inclusion"]["path"][0]["hash"][2:]), ".F"),
        ("sig upper", lambda b: _set(b, ("milestone", "signatures", 1, "sig"),
                                     b["milestone"]["signatures"][1]["sig"].upper()), "..F"),
        ("pk no 0x", lambda b: _set(b, ("milestone", "signatures", 0, "pk"),
                                    b["milestone"]["signatures"][0]["pk"][2:]), "..F"),
        ("essence 0X", lambda b: _set(b, ("milestone", "essence"),
                                      "0X" + b["milestone"]["essence"][2:]), ".FF.F"),
        ("msPath upper", lambda b: _set(b, ("anchor", "msPath", 0, "hash"),
                                        b["anchor"]["msPath"][0]["hash"].upper()), "....F"),
    ],
)
def test_non_canonical_hex_is_rejected(vectors, syn, where, mutate, expect):
    """Verifier inputs are strict lowercase 0x-hex; the step that reads the field fails."""
    b = mutate(copy.deepcopy(syn.bundle))
    ladder = bundle.verify(b, _cfg(vectors), _fetch(syn.record), _registry())
    for i, step in enumerate(ladder.steps):
        if i < len(expect) and expect[i] == "F":
            assert step.ok is False, (where, step)
            assert "non-canonical hex" in step.detail, (where, step)
        elif step.name != "envelope":  # step 4 is None when raw cannot be read
            assert step.ok is True, (where, step)
    assert ladder.overall == "INVALID"


def test_raw_that_does_not_parse(vectors):
    b = _real_bundle(vectors)
    raw = from_hex(b["block"]["raw"]) + b"\x00"
    b["block"]["raw"] = to_hex(raw)
    b["block"]["id"] = to_hex(blake2b256(raw))
    ladder = bundle.verify(b, _cfg(vectors))
    assert _step(ladder, "block_hash").ok is False
    assert "parse" in _step(ladder, "block_hash").detail
    assert _step(ladder, "envelope").ok is None


# ---------------------------------------------------------------- step 4 envelope


def test_envelope_step_producer_signed(vectors, syn):
    ladder = bundle.verify(syn.bundle, _cfg(vectors), resolve_did=_registry())
    assert _ok(ladder) == "TTTTN PARTIAL"
    assert verdicts.PRODUCER_SIGNED in _step(ladder, "envelope").detail


def test_envelope_needs_trusted_resolver(vectors, syn):
    """The bundle's own snapshot never turns step 4 green."""
    ladder = bundle.verify(syn.bundle, _cfg(vectors), _fetch(syn.record))
    assert _ok(ladder) == "TTTNT PARTIAL"
    assert _step(ladder, "envelope").detail == bundle.UNRESOLVED_SIGNER
    for registry in (lambda did: None, _boom):
        step = _step(bundle.verify(syn.bundle, _cfg(vectors), resolve_did=registry), "envelope")
        assert (step.ok, step.detail) == (None, bundle.UNRESOLVED_SIGNER)


def test_self_made_snapshot_is_not_trusted(vectors):
    """A forger signs with their own key and ships a snapshot listing that key."""
    forger = ATTACKERS[0]
    s = _synthetic(vectors, _envelope(sign_key=forger), snapshot=_snapshot(signer=forger))
    assert s.bundle["envelope"]["verdict"] == verdicts.PRODUCER_SIGNED  # against its own snapshot
    alone = bundle.verify(s.bundle, _cfg(vectors), _fetch(s.record))
    assert _ok(alone) == "TTTNT PARTIAL"
    resolved = bundle.verify(s.bundle, _cfg(vectors), _fetch(s.record), _registry())
    assert _ok(resolved) == "TTTFT INVALID"
    assert verdicts.FORGED in _step(resolved, "envelope").detail


def test_envelope_step_relay_attested(vectors):
    s = _synthetic(vectors, _envelope(att_mode="relay", att_sub="kc-user-1"))
    step = _step(bundle.verify(s.bundle, _cfg(vectors), resolve_did=_registry()), "envelope")
    assert step.ok is True
    assert verdicts.RELAY_ATTESTED in step.detail


def test_envelope_forged_ignores_claimed_verdict(vectors):
    env = _envelope()
    forged = {**env, "body": {"score": 0.99, "id": "MyDomain:fa163e5e25ef"}}
    lie = EnvelopeCheck(verdicts.PRODUCER_SIGNED, DID, KID, 1, NOW_MS, None)
    s = _synthetic(vectors, forged, claimed=lie)
    assert s.bundle["envelope"]["verdict"] == verdicts.PRODUCER_SIGNED
    ladder = bundle.verify(s.bundle, _cfg(vectors), _fetch(s.record), _registry())
    assert _ok(ladder) == "TTTFT INVALID"
    assert verdicts.FORGED in _step(ladder, "envelope").detail


def test_key_independent_failures_need_no_resolver(vectors):
    """Malformed envelopes and tag or kid mismatches are red even without a registry."""
    retagged = envelope.seal(
        "LLO-K8s", {"event": "x"}, iss=DID, kid=KID, sign_key=SIGNER, seq=1,
        att_mode="producer", now_ms=NOW_MS, nonce=bytes(range(16)),
    )
    step = _step(bundle.verify(_synthetic(vectors, retagged).bundle, _cfg(vectors)), "envelope")
    assert step.ok is False and verdicts.FORGED in step.detail
    foreign_kid = _synthetic(vectors, _envelope(kid="did:iota:testnet:0xother#sig-1"))
    assert _step(bundle.verify(foreign_kid.bundle, _cfg(vectors)), "envelope").ok is False
    malformed = _envelope()
    malformed["seq"] = "1"
    step = _step(bundle.verify(_synthetic(vectors, malformed).bundle, _cfg(vectors)), "envelope")
    assert step.ok is False and verdicts.MALFORMED in step.detail


def test_key_missing_from_resolved_document(vectors):
    other = Ed25519PrivateKey.from_private_bytes(b"\x0c" * 32)
    s = _synthetic(vectors, _envelope(sign_key=other))
    step = _step(bundle.verify(s.bundle, _cfg(vectors), resolve_did=_registry()), "envelope")
    assert step.ok is False
    doc = _snapshot()
    doc["keys"] = doc["keys"][1:]  # only the X25519 key left
    step = _step(bundle.verify(s.bundle, _cfg(vectors), resolve_did=_registry(doc)), "envelope")
    assert step.ok is False


def test_resolved_document_must_belong_to_issuer(vectors, syn):
    doc = _snapshot()
    doc["doc"]["id"] = "did:iota:testnet:0xother"
    step = _step(bundle.verify(syn.bundle, _cfg(vectors), resolve_did=lambda did: doc), "envelope")
    assert (step.ok, step.detail) == (False, "resolved DID document does not belong to the issuer")
    for bad in ({"doc": {"id": DID}, "keys": "nope"}, {"keys": []}, [], "x"):
        ladder = bundle.verify(syn.bundle, _cfg(vectors), resolve_did=lambda did, d=bad: d)
        assert _step(ladder, "envelope").ok is False, bad


def test_snapshot_must_match_resolved_document(vectors):
    """Honest signature under the registry key, but the bundle snapshot shows another key."""
    s = _synthetic(vectors, _envelope(), snapshot=_snapshot(signer=ATTACKERS[1]))
    step = _step(bundle.verify(s.bundle, _cfg(vectors), resolve_did=_registry()), "envelope")
    assert (step.ok, step.detail) == (False, "DID snapshot does not match resolved document")
    for snap in ({"keys": "nope"}, {"doc": {"id": DID}, "keys": []}):
        b = copy.deepcopy(s.bundle)
        b["envelope"]["didDoc"] = snap
        step = _step(bundle.verify(b, _cfg(vectors), resolve_did=_registry()), "envelope")
        assert step.ok is False, snap


def test_envelope_without_snapshot_uses_registry(vectors, syn):
    b = copy.deepcopy(syn.bundle)
    b["envelope"]["didDoc"] = None
    assert _step(bundle.verify(b, _cfg(vectors)), "envelope").ok is None
    assert _step(bundle.verify(b, _cfg(vectors), resolve_did=_registry()), "envelope").ok is True
    b["envelope"] = None
    assert _step(bundle.verify(b, _cfg(vectors), resolve_did=_registry()), "envelope").ok is True


def test_envelope_revocation_is_time_aware(vectors, syn):
    ms_time_ms = (vectors("milestones")[-1]["timestamp"] + 5) * 1000
    revoked = _registry(_snapshot(revoked_at_ms=ms_time_ms - 1))
    step = _step(bundle.verify(syn.bundle, _cfg(vectors), resolve_did=revoked), "envelope")
    assert (step.ok, step.detail) == (False, "key revoked before inclusion")
    for later in (ms_time_ms, ms_time_ms + 1000):
        registry = _registry(_snapshot(revoked_at_ms=later))
        ladder = bundle.verify(syn.bundle, _cfg(vectors), resolve_did=registry)
        assert _step(ladder, "envelope").ok is True, later
    # Revocation is read from the registry, not from the bundle's snapshot.
    s = _synthetic(vectors, _envelope(), snapshot=_snapshot(revoked_at_ms=ms_time_ms - 1))
    ladder = bundle.verify(s.bundle, _cfg(vectors), resolve_did=_registry())
    assert _step(ladder, "envelope").ok is True


def test_snapshot_resolver_shapes():
    resolve = bundle.snapshot_resolver(_snapshot(revoked_at_ms=5))
    info = resolve(KID)
    assert info is not None
    assert info.ed25519_public == SIGNER.public_key().public_bytes_raw()
    assert info.revoked_at_ms == 5
    kex = resolve(DID + "#kex-1")
    assert kex is not None and kex.ed25519_public is None
    assert kex.x25519_public == KEX.public_key().public_bytes_raw()
    assert resolve("did:iota:testnet:0xother#sig-1") is None
    # Fragment-only kids are resolved against the document id.
    snap = _snapshot()
    snap["keys"][0]["kid"] = "#sig-1"
    assert bundle.snapshot_resolver(snap)(KID) is not None
    # Keys that belong to another DID are not served for this document.
    snap = _snapshot()
    snap["keys"][0]["kid"] = "did:iota:testnet:0xother#sig-1"
    assert bundle.snapshot_resolver(snap)("did:iota:testnet:0xother#sig-1") is None
    with pytest.raises(ValueError):
        bundle.snapshot_resolver({"doc": {"id": DID}, "keys": None})


OLD_SIGNER = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)


def _ed_entry(signer: Ed25519PrivateKey, revoked_at_ms: int | None, kid: str = KID) -> dict:
    return {
        "kid": kid,
        "type": "Ed25519",
        "publicKeyHex": to_hex(signer.public_key().public_bytes_raw()),
        "revokedAtMs": revoked_at_ms,
    }


def _replaced(replaced_at_ms: int) -> dict:
    """`#sig-1` replaced in place: the anchor lists current keys first, then revoked ones."""
    snap = _snapshot()
    snap["keys"].append(_ed_entry(OLD_SIGNER, replaced_at_ms))
    return snap


def _pub(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes_raw()


def test_snapshot_resolver_replaced_key_is_chosen_by_time():
    resolve = bundle.snapshot_resolver(_replaced(1000))
    # Without a time: the key in the current document.
    assert resolve(KID).ed25519_public == _pub(SIGNER)
    assert resolve(KID).revoked_at_ms is None
    # Before (and at) the replacement the old key was in force.
    for at in (0, 999, 1000):
        info = resolve(KID, at)
        assert (info.ed25519_public, info.revoked_at_ms) == (_pub(OLD_SIGNER), 1000), at
    assert resolve(KID, 1001).ed25519_public == _pub(SIGNER)
    # The X25519 key of the same document is unaffected.
    assert resolve(DID + "#kex-1", 5).x25519_public == KEX.public_key().public_bytes_raw()


def test_snapshot_resolver_all_revoked_and_ties():
    k1, k2, k3 = (Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32) for n in (0x21, 0x22, 0x23))
    snap = {"doc": {"id": DID}, "keys": [_ed_entry(k1, 10), _ed_entry(k2, 20)]}
    resolve = bundle.snapshot_resolver(snap)
    assert resolve(KID, 5).ed25519_public == _pub(k1)
    assert resolve(KID, 15).ed25519_public == _pub(k2)
    # Nothing valid any more: the key revoked last, so callers see the revocation.
    for at in (None, 25):
        info = resolve(KID, at)
        assert (info.ed25519_public, info.revoked_at_ms) == (_pub(k2), 20)
    # Equal validity: the entry listed last wins.
    snap = {"doc": {"id": DID}, "keys": [_ed_entry(k1, None), _ed_entry(k3, None)]}
    assert bundle.snapshot_resolver(snap)(KID).ed25519_public == _pub(k3)


@pytest.mark.parametrize(
    "bad",
    [
        {"publicKeyHex": "0xzz"},
        {"publicKeyHex": "0x" + "11" * 31},
        {"revokedAtMs": "1000"},
        {"revokedAtMs": -1},
        {"revokedAtMs": True},
        {"type": "RSA"},
    ],
)
def test_snapshot_resolver_unreadable_entry_fails_closed(bad):
    """An entry for a kid that cannot be read makes the kid unresolvable, never a guess."""
    snap = _replaced(1000)
    snap["keys"][-1].update(bad)
    resolve = bundle.snapshot_resolver(snap)
    assert resolve(KID) is None and resolve(KID, 5) is None
    assert resolve(DID + "#kex-1") is not None  # other kids are still served


def test_snapshot_keys_lists_every_entry():
    keys = bundle.snapshot_keys(_replaced(1000))
    assert [(k.ed25519_public, k.revoked_at_ms) for k in keys[KID]] == [
        (_pub(SIGNER), None),
        (_pub(OLD_SIGNER), 1000),
    ]
    assert bundle.snapshot_keys({"doc": {"id": DID}, "keys": [{"kid": KID}]}) == {}


def test_envelope_signed_with_a_replaced_key(vectors):
    """A message signed before its key was replaced still verifies; one included after the
    replacement does not, and the new key verifies new messages."""
    ms_time_ms = (vectors("milestones")[-1]["timestamp"] + 5) * 1000
    later, earlier = _replaced(ms_time_ms + 1), _replaced(ms_time_ms - 1)
    old = _synthetic(vectors, _envelope(sign_key=OLD_SIGNER), snapshot=later)
    step = _step(bundle.verify(old.bundle, _cfg(vectors), resolve_did=_registry(later)), "envelope")
    assert step.ok is True, step.detail
    step = _step(
        bundle.verify(old.bundle, _cfg(vectors), resolve_did=_registry(earlier)), "envelope"
    )
    assert step.ok is False
    new = _synthetic(vectors, _envelope(), snapshot=earlier)
    step = _step(
        bundle.verify(new.bundle, _cfg(vectors), resolve_did=_registry(earlier)), "envelope"
    )
    assert step.ok is True, step.detail


# ---------------------------------------------------------------- step 5 anchor


def test_anchor_membership(vectors, syn):
    calls = []

    def fetch(anchor):
        calls.append(anchor)
        return dict(syn.record)

    ladder = bundle.verify(syn.bundle, _cfg(vectors), fetch, _registry())
    assert _ok(ladder) == "TTTTT VALID"
    assert calls and calls[0]["rebased"] == REBASED
    assert len(syn.window) == 5 and syn.milestone_id in syn.window
    by_checkpoint = bundle.verify(
        syn.bundle, _cfg(vectors), _fetch({"checkpoint": syn.checkpoint}), _registry()
    )
    assert _ok(by_checkpoint) == "TTTTT VALID"


def test_anchor_mismatch(vectors, syn):
    other = {**syn.checkpoint, "msRoot": to_hex(b"\x42" * 32)}
    ladder = bundle.verify(syn.bundle, _cfg(vectors), _fetch({"checkpoint": other}), _registry())
    assert _ok(ladder) == "TTTTF INVALID"
    assert _step(ladder, "anchor").detail == "checkpoint does not match on-chain record"
    by_hash = {"checkpointHash": to_hex(checkpoint.hash(other))}
    assert _step(bundle.verify(syn.bundle, _cfg(vectors), _fetch(by_hash)), "anchor").ok is False
    both = {"checkpointHash": syn.record["checkpointHash"], "checkpoint": other}
    assert _step(bundle.verify(syn.bundle, _cfg(vectors), _fetch(both)), "anchor").ok is False


def test_anchor_not_in_window(vectors):
    real = [from_hex(m["milestoneId"]) for m in vectors("milestones")]
    # Same index range, but the anchored id at 374 is a different milestone.
    s = _synthetic(vectors, _envelope(), window_override=[*real, blake2b256(b"other 374")])
    ladder = bundle.verify(s.bundle, _cfg(vectors), _fetch(s.record), _registry())
    assert _ok(ladder) == "TTTTF INVALID"
    assert _step(ladder, "anchor").detail == "milestone not in anchored checkpoint"
    # A window that ends before our milestone.
    early = [blake2b256(f"ms {i}".encode()) for i in range(5)]
    s = _synthetic(vectors, _envelope(), window_override=early)
    s.bundle["anchor"]["checkpoint"]["to"]["index"] = 373  # keep the window shape valid
    s.bundle["anchor"]["checkpoint"]["from"]["index"] = 369
    record = {"checkpointHash": to_hex(checkpoint.hash(s.bundle["anchor"]["checkpoint"]))}
    step = _step(bundle.verify(s.bundle, _cfg(vectors), _fetch(record)), "anchor")
    assert (step.ok, step.detail) == (False, "milestone not in anchored checkpoint")


def test_anchor_unavailable(vectors, syn):
    ladder = bundle.verify(syn.bundle, _cfg(vectors), _fetch(None), _registry())
    assert _ok(ladder) == "TTTTN PARTIAL"
    assert _step(ladder, "anchor").detail == "anchor record unavailable"

    def boom(anchor):
        raise OSError("rpc down")

    step = _step(bundle.verify(syn.bundle, _cfg(vectors), boom), "anchor")
    assert step.ok is None and step.detail.startswith("anchor record unavailable")


def test_anchor_not_evaluated_without_fetcher_or_anchor(vectors, syn):
    step = _step(bundle.verify(syn.bundle, _cfg(vectors)), "anchor")
    assert (step.ok, step.detail) == (None, "anchor not checked: no record fetcher")
    b = copy.deepcopy(syn.bundle)
    b["anchor"] = None
    assert _step(bundle.verify(b, _cfg(vectors), _fetch(syn.record)), "anchor").ok is None


def test_anchor_offline_failures_need_no_fetcher(vectors):
    """Only "matches the chain" needs the record; local contradictions are red without it."""
    real = [from_hex(m["milestoneId"]) for m in vectors("milestones")]
    outside = _synthetic(vectors, _envelope(), window_override=[*real, blake2b256(b"other 374")])
    ladder = bundle.verify(outside.bundle, _cfg(vectors), resolve_did=_registry())
    assert _ok(ladder) == "TTTTF INVALID"
    assert _step(ladder, "anchor").detail == "milestone not in anchored checkpoint"
    good = _synthetic(vectors, _envelope())
    wrong_trail = _cfg(vectors, trail_id="0x" + "00" * 32)
    assert _step(bundle.verify(good.bundle, wrong_trail), "anchor").ok is False
    bad_cp = copy.deepcopy(good.bundle)
    bad_cp["anchor"]["checkpoint"]["kind"] = "other"
    assert _step(bundle.verify(bad_cp, _cfg(vectors)), "anchor").ok is False
    bad_record = copy.deepcopy(good.bundle)
    bad_record["anchor"]["rebased"]["record"] = "3"
    assert _step(bundle.verify(bad_record, _cfg(vectors)), "anchor").ok is False


def test_anchor_requires_pinned_trail(vectors, syn):
    for unpinned in (
        _cfg(vectors, trail_id=None, rebased_network=None),
        _cfg(vectors, trail_id=None),
        _cfg(vectors, rebased_network=None),
    ):
        step = _step(bundle.verify(syn.bundle, unpinned, _fetch(syn.record)), "anchor")
        assert step.ok is None, unpinned
        assert step.detail == "anchor not checked: verifier pins no Rebased trail"
    other_trail = _cfg(vectors, trail_id="0x" + "00" * 32)
    assert _step(bundle.verify(syn.bundle, other_trail, _fetch(syn.record)), "anchor").ok is False
    other_net = _cfg(vectors, rebased_network="mainnet")
    assert _step(bundle.verify(syn.bundle, other_net, _fetch(syn.record)), "anchor").ok is False


def test_anchor_network_must_match(vectors, syn):
    b = copy.deepcopy(syn.bundle)
    b["anchor"]["checkpoint"]["network"] = "another_tangle"
    record = {"checkpointHash": to_hex(checkpoint.hash(b["anchor"]["checkpoint"]))}
    assert _step(bundle.verify(b, _cfg(vectors), _fetch(record)), "anchor").ok is False
    assert _step(
        bundle.verify(syn.bundle, _cfg(vectors, network="another_tangle"), _fetch(syn.record)),
        "anchor",
    ).ok is False


@pytest.mark.parametrize(
    "record", [{}, [], "0x00", {"checkpointHash": "zz"}, {"checkpointHash": "0x00"}, 5]
)
def test_anchor_malformed_record(vectors, syn, record):
    assert _step(bundle.verify(syn.bundle, _cfg(vectors), _fetch(record)), "anchor").ok is False


# ---------------------------------------------------------------- robustness


@pytest.mark.parametrize("bad", [None, [], "x", 5, {}, {"v": 2}, {"v": True}])
def test_verify_rejects_non_bundles(vectors, bad):
    ladder = bundle.verify(bad, _cfg(vectors), _fetch(None))
    assert ladder.overall == "INVALID"
    assert [s.name for s in ladder.steps] == STEPS


_json = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**70), max_value=2**70)
    | st.floats()
    | st.text(max_size=12)
    | st.sampled_from(["0x", "0x00", "0x" + "00" * 32, "0x" + "00" * 64, "L", "R", "0xzz"]),
    lambda inner: (
        st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=8), inner, max_size=4)
    ),
    max_leaves=12,
)
_TOP = ["v", "network", "block", "milestone", "inclusion", "envelope", "anchor"]
_EXAMPLES = int(os.environ.get("HYP_EXAMPLES", "60"))


def _paths(obj: Any, prefix: tuple = ()) -> list[tuple]:
    out = [prefix] if prefix else []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _paths(v, (*prefix, k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += _paths(v, (*prefix, i))
    return out


@settings(max_examples=_EXAMPLES, deadline=None)
@given(
    st.dictionaries(st.sampled_from(_TOP) | st.text(max_size=6), _json, max_size=8),
    _json,
    _json,
)
def test_verify_never_raises(vectors, d, record, doc):
    ladder = bundle.verify(d, _cfg(vectors), _fetch(record), lambda did: copy.deepcopy(doc))
    assert isinstance(ladder, Ladder)
    assert [s.name for s in ladder.steps] == STEPS


@settings(max_examples=_EXAMPLES, deadline=None)
@given(st.data())
def test_verify_never_raises_on_mutated_bundle(vectors, syn, data):
    b = copy.deepcopy(syn.bundle)
    path = data.draw(st.sampled_from(_paths(b)))
    target = b
    for key in path[:-1]:
        target = target[key]
    if data.draw(st.booleans()) and isinstance(target, dict):
        del target[path[-1]]
    else:
        target[path[-1]] = data.draw(_json)
    record = data.draw(st.sampled_from([syn.record, None]) | _json)
    doc = data.draw(st.sampled_from([_snapshot(), None]) | _json)
    ladder = bundle.verify(b, _cfg(vectors), _fetch(record), lambda did: copy.deepcopy(doc))
    assert isinstance(ladder, Ladder)
    assert ladder.overall in ("VALID", "INVALID", "PARTIAL")


# ---------------------------------------------------------------- vectors for the TS port


def _config_json(cfg: VerifierConfig) -> dict:
    return {
        "network": cfg.network,
        "trustedCoordinatorKeys": sorted(to_hex(k) for k in cfg.trusted_coordinator_keys),
        "threshold": cfg.threshold,
        "rebasedNetwork": cfg.rebased_network,
        "trailId": cfg.trail_id,
    }


def _case(
    name: str, b: dict, cfg: VerifierConfig, fetcher: Any, resolver: str | None, expect: str
) -> dict:
    marks, overall = expect.split()
    return {
        "name": name,
        "bundle": b,
        "config": _config_json(cfg),
        "fetcher": fetcher,
        "resolver": resolver,
        "expected": {
            "overall": overall,
            "steps": [
                {"name": n, "ok": {"T": True, "F": False, "N": None}[m]}
                for n, m in zip(STEPS, marks, strict=True)
            ],
        },
    }


def _registries(vectors) -> dict[str, dict[str, dict]]:
    """Trusted DID registries the cases refer to by name: {name: {did: resolve doc}}."""
    ms_time_ms = (vectors("milestones")[-1]["timestamp"] + 5) * 1000
    wrong_issuer = _snapshot()
    wrong_issuer["doc"]["id"] = "did:iota:testnet:0xother"
    return {
        "registry": {DID: _snapshot()},
        "registry_key_revoked": {DID: _snapshot(revoked_at_ms=ms_time_ms - 1)},
        "registry_key_revoked_at_inclusion": {DID: _snapshot(revoked_at_ms=ms_time_ms)},
        "registry_key_revoked_after_inclusion": {DID: _snapshot(revoked_at_ms=ms_time_ms + 1000)},
        "registry_wrong_issuer": {DID: wrong_issuer},
        "registry_weak_key": {DID: _weak_signer_snapshot()},
    }


def _dup_sig(b: dict) -> dict:
    out = copy.deepcopy(b)
    out["milestone"]["signatures"] = [out["milestone"]["signatures"][0]] * 2
    return out


def _cases(vectors) -> list[dict]:
    cfg = _cfg(vectors)
    good = _synthetic(vectors, _envelope())
    b, rec = good.bundle, {"record": good.record}
    env = _envelope()
    forged = _synthetic(
        vectors,
        {**env, "body": {"score": 0.99, "id": "MyDomain:fa163e5e25ef"}},
        claimed=EnvelopeCheck(verdicts.PRODUCER_SIGNED, DID, KID, 1, NOW_MS, None),
    )
    forger = ATTACKERS[0]
    self_made = _synthetic(vectors, _envelope(sign_key=forger), snapshot=_snapshot(signer=forger))
    stale_snapshot = _synthetic(vectors, env, snapshot=_snapshot(signer=ATTACKERS[1]))
    real = [from_hex(m["milestoneId"]) for m in vectors("milestones")]
    outside = _synthetic(vectors, env, window_override=[*real, blake2b256(b"other 374")])
    mismatch = {"checkpoint": {**good.checkpoint, "msRoot": to_hex(b"\x42" * 32)}}
    untrusted = _cfg(vectors, trusted_coordinator_keys=ATTACKER_PUBS)
    malformed_env = _envelope()
    malformed_env["seq"] = "1"
    malformed = _synthetic(vectors, malformed_env)
    retagged = _synthetic(
        vectors,
        envelope.seal(
            "LLO-K8s", {"event": "x"}, iss=DID, kid=KID, sign_key=SIGNER, seq=1,
            att_mode="producer", now_ms=NOW_MS, nonce=bytes(range(16)),
        ),
    )
    upper_raw = _set(copy.deepcopy(b), ("block", "raw"), b["block"]["raw"].upper())
    upper_id = _set(copy.deepcopy(b), ("block", "id"), "0x" + b["block"]["id"][2:].upper())
    bare_path = _set(
        copy.deepcopy(b), ("inclusion", "path", 0, "hash"), b["inclusion"]["path"][0]["hash"][2:]
    )
    upper_sig = _set(
        copy.deepcopy(b),
        ("milestone", "signatures", 1, "sig"),
        b["milestone"]["signatures"][1]["sig"].upper(),
    )
    upper_ms_path = _set(
        copy.deepcopy(b), ("anchor", "msPath", 0, "hash"), b["anchor"]["msPath"][0]["hash"].upper()
    )
    weak_pinned = _cfg(
        vectors,
        trusted_coordinator_keys={from_hex(k) for k in vectors("coordinator_keys")["publicKeys"]}
        | {IDENTITY},
    )
    weak_signer = _synthetic(
        vectors,
        _weak_signed(),
        snapshot=_weak_signer_snapshot(),
        claimed=EnvelopeCheck(verdicts.PRODUCER_SIGNED, DID, KID, 1, NOW_MS, None),
    )
    reg = "registry"
    return [
        _case("valid_anchored", b, cfg, rec, reg, "TTTTT VALID"),
        _case("partial_real_no_anchor", _real_bundle(vectors), cfg, None, None, "TTTNN PARTIAL"),
        _case("anchor_unreachable", b, cfg, {"record": None}, reg, "TTTTN PARTIAL"),
        _case("signer_unresolved", b, cfg, rec, None, "TTTNT PARTIAL"),
        _case("raw_byte_flipped", _flip_raw(b), cfg, rec, reg, "FTTTT INVALID"),
        _case("path_hash_corrupted", _corrupt_path(b), cfg, rec, reg, "TFTTT INVALID"),
        _case("signature_corrupted", _corrupt_sig(b), cfg, rec, reg, "TTFTT INVALID"),
        _case("one_signature_threshold_2", _drop_sig(b), cfg, rec, reg, "TTFTT INVALID"),
        _case("untrusted_key_set", b, untrusted, rec, reg, "TTFTT INVALID"),
        _case(
            "envelope_forged", forged.bundle, cfg, {"record": forged.record}, reg, "TTTFT INVALID"
        ),
        _case(
            "self_made_snapshot_unresolved",
            self_made.bundle,
            cfg,
            {"record": self_made.record},
            None,
            "TTTNT PARTIAL",
        ),
        _case(
            "self_made_snapshot_resolved",
            self_made.bundle,
            cfg,
            {"record": self_made.record},
            reg,
            "TTTFT INVALID",
        ),
        _case(
            "snapshot_differs_from_registry",
            stale_snapshot.bundle,
            cfg,
            {"record": stale_snapshot.record},
            reg,
            "TTTFT INVALID",
        ),
        _case("key_revoked_before_inclusion", b, cfg, rec, "registry_key_revoked", "TTTFT INVALID"),
        _case("resolved_doc_not_issuer", b, cfg, rec, "registry_wrong_issuer", "TTTFT INVALID"),
        _case("anchor_mismatch", b, cfg, {"record": mismatch}, reg, "TTTTF INVALID"),
        _case(
            "milestone_not_in_window",
            outside.bundle,
            cfg,
            {"record": outside.record},
            reg,
            "TTTTF INVALID",
        ),
        _case("milestone_not_in_window_no_fetcher", outside.bundle, cfg, None, reg,
              "TTTTF INVALID"),
        _case("duplicate_signature_counted_once", _dup_sig(b), cfg, rec, reg, "TTFTT INVALID"),
        _case("key_revoked_at_inclusion", b, cfg, rec, "registry_key_revoked_at_inclusion",
              "TTTTT VALID"),
        _case("key_revoked_after_inclusion", b, cfg, rec, "registry_key_revoked_after_inclusion",
              "TTTTT VALID"),
        _case("trail_unpinned", b, _cfg(vectors, trail_id=None), rec, reg, "TTTTN PARTIAL"),
        _case("rebased_network_unpinned", b, _cfg(vectors, rebased_network=None), rec, reg,
              "TTTTN PARTIAL"),
        _case("bundle_root_ignored", _with_fake_root(b), cfg, rec, reg, "TFTTT INVALID"),
        _case("envelope_malformed_no_resolver", malformed.bundle, cfg,
              {"record": malformed.record}, None, "TTTFT INVALID"),
        _case("envelope_retagged_no_resolver", retagged.bundle, cfg,
              {"record": retagged.record}, None, "TTTFT INVALID"),
        _case("bundle_network_not_pinned", _real_bundle(vectors),
              _cfg(vectors, network="another_tangle"), None, None, "TTFNN INVALID"),
        _case("noncanonical_hex_raw", upper_raw, cfg, rec, reg, "FTTNT INVALID"),
        _case("noncanonical_hex_block_id", upper_id, cfg, rec, reg, "FFTTT INVALID"),
        _case("noncanonical_hex_inclusion_path", bare_path, cfg, rec, reg, "TFTTT INVALID"),
        _case("noncanonical_hex_signature", upper_sig, cfg, rec, reg, "TTFTT INVALID"),
        _case("noncanonical_hex_ms_path", upper_ms_path, cfg, rec, reg, "TTTTF INVALID"),
        _case("small_order_coordinator_key_not_counted", _weak_coordinator(b), weak_pinned, rec,
              reg, "TTFTT INVALID"),
        _case("small_order_signer_key", weak_signer.bundle, cfg, {"record": weak_signer.record},
              "registry_weak_key", "TTTFT INVALID"),
    ]


def _verify_case(case: dict, registries: dict[str, dict[str, dict]]) -> Ladder:
    c = case["config"]
    cfg = VerifierConfig(
        network=c["network"],
        trusted_coordinator_keys={from_hex(k) for k in c["trustedCoordinatorKeys"]},
        threshold=c["threshold"],
        rebased_network=c["rebasedNetwork"],
        trail_id=c["trailId"],
    )
    fetcher = None if case["fetcher"] is None else _fetch(case["fetcher"]["record"])
    resolver = None
    if case["resolver"] is not None:
        docs = registries[case["resolver"]]
        resolver = lambda did: copy.deepcopy(docs.get(did))
    return bundle.verify(case["bundle"], cfg, fetcher, resolver)


def test_write_bundle_vectors(vectors):
    data = {
        "description": (
            "witness-proof/v1 bundles. For each case run "
            "verify(bundle, config, fetcher, resolver). fetcher null = no anchor fetcher; "
            "otherwise the fetcher returns fetcher.record (null = record unavailable). "
            "resolver null = no trusted DID resolver; otherwise resolve(did) returns "
            "resolvers[resolver][did] or null when absent. Compare ok per step "
            "(null = not evaluated) and overall."
        ),
        "resolvers": _registries(vectors),
        "cases": _cases(vectors),
    }
    if not VECTORS.exists() or os.environ.get("WITNESS_REGEN_VECTORS") == "1":
        VECTORS.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    stored = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert stored == json.loads(json.dumps(data))
    for case in stored["cases"]:
        ladder = _verify_case(case, stored["resolvers"])
        got = {
            "overall": ladder.overall,
            "steps": [{"name": s.name, "ok": s.ok} for s in ladder.steps],
        }
        assert got == case["expected"], (case["name"], ladder)
    names = [c["name"] for c in stored["cases"]]
    assert len(names) == len(set(names))
