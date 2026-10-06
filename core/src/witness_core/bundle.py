"""`witness-proof/v1` bundles and the offline verifier ladder.

A bundle carries raw block bytes, the milestone essence and its signatures,
the Merkle audit path, a DID document snapshot and, optionally, an anchor
checkpoint. The verifier trusts only its pinned `VerifierConfig` plus two
trusted lookups (on-chain anchor record, DID registry) and recomputes every id
and root from raw bytes; claims written into the bundle (block id aside, which
step 1 checks) are cross-checked, never relied on. The DID snapshot is for
offline display only: it is attacker-controlled, so it never authenticates a
signer, it can only contradict the registry.

Ladder: 1 block_hash, 2 inclusion, 3 milestone_signatures, 4 envelope,
5 anchor. Each step is ok (True), failed (False) or not evaluated (None).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import checkpoint, codec, envelope, merkle, verdicts
from .codec import Ed25519Sig, MilestoneEssence
from .envelope import EnvelopeCheck, KeyInfo
from .ids import blake2b256, from_hex, to_hex

StepName = Literal["block_hash", "inclusion", "milestone_signatures", "envelope", "anchor"]
Overall = Literal["VALID", "INVALID", "PARTIAL"]
STEP_NAMES: tuple[StepName, ...] = (
    "block_hash", "inclusion", "milestone_signatures", "envelope", "anchor",
)
VERSION = 1
_MAX_INT = 2**53 - 1
_KEY_SLOTS = {"Ed25519": "ed", "X25519": "x"}


@dataclass(frozen=True)
class VerifierConfig:
    """What the verifier pins out of band; everything else comes from the bundle."""

    network: str
    trusted_coordinator_keys: set[bytes]
    threshold: int
    rebased_network: str | None = None
    trail_id: str | None = None


@dataclass(frozen=True)
class StepResult:
    name: StepName
    ok: bool | None
    detail: str


@dataclass(frozen=True)
class Ladder:
    steps: list[StepResult]
    overall: Overall


class _Fail(Exception):
    """The step failed; the message is its detail."""


class _Skip(Exception):
    """The step cannot be evaluated; the message is its detail."""


# ---------------------------------------------------------------- build


def _path_json(path: list[Any]) -> list[Any]:
    return [
        {"side": s.side, "hash": to_hex(s.hash)} if isinstance(s, merkle.PathStep) else s
        for s in path
    ]


def _parse_essence(essence_bytes: bytes) -> MilestoneEssence:
    """Decode a bare essence by wrapping it as a milestone payload with no signatures."""
    wrapped = codec.PAYLOAD_MILESTONE.to_bytes(4, "little") + essence_bytes + b"\x00"
    return codec.parse_milestone_payload(wrapped).essence


def build(
    *,
    network: str,
    block_raw: bytes,
    milestone_essence: bytes,
    milestone_sigs: list[Ed25519Sig],
    cone_ids: list[bytes],
    envelope_check: EnvelopeCheck | None,
    did_doc_snapshot: dict | None,
    anchor: dict | None,
) -> dict:
    """Assemble a bundle. `cone_ids` is the milestone's white-flag ordered cone."""
    bid = codec.block_id(block_raw)
    try:
        leaf_index = cone_ids.index(bid)
    except ValueError:
        raise ValueError(f"block {to_hex(bid)} is not in the milestone cone") from None
    essence = _parse_essence(milestone_essence)
    env_section = None
    if envelope_check is not None or did_doc_snapshot is not None:
        version = did_doc_snapshot.get("version") if isinstance(did_doc_snapshot, dict) else None
        env_section = {
            "verdict": None if envelope_check is None else envelope_check.verdict,
            "didDoc": did_doc_snapshot,
            "didVersion": version,
        }
    anchor_section = None
    if anchor is not None:
        anchor_section = dict(anchor)
        if isinstance(anchor_section.get("msPath"), list):
            anchor_section["msPath"] = _path_json(anchor_section["msPath"])
    return {
        "v": VERSION,
        "network": network,
        "block": {"id": to_hex(bid), "raw": to_hex(block_raw)},
        "milestone": {
            "index": essence.index,
            "id": to_hex(codec.milestone_id(milestone_essence)),
            "essence": to_hex(milestone_essence),
            "signatures": [
                {"pk": to_hex(s.public_key), "sig": to_hex(s.signature)} for s in milestone_sigs
            ],
        },
        "inclusion": {
            "leafIndex": leaf_index,
            "leafCount": len(cone_ids),
            "path": _path_json(merkle.audit_path(cone_ids, leaf_index)),
        },
        "envelope": env_section,
        "anchor": anchor_section,
    }


# ---------------------------------------------------------------- DID snapshot


def _key_bytes(entry: dict) -> bytes | None:
    pk = entry.get("publicKeyHex")
    if not isinstance(pk, str):
        return None
    try:
        raw = from_hex(pk)
    except ValueError:
        return None
    return raw if len(raw) == 32 else None


def snapshot_resolver(snapshot: dict) -> Callable[[str], KeyInfo | None]:
    """Key lookup over a DID document snapshot in the anchor service's resolve shape.

    `{"doc": {"id": did, ...}, "version": ..., "keys": [{"kid", "type", "publicKeyHex",
    "revokedAtMs"}]}`. Fragment kids (`#sig-1`) are expanded against `doc.id`; keys that
    name another DID are ignored. Raises ValueError if the snapshot is not usable.
    """
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("keys"), list):
        raise ValueError("DID snapshot must be an object with a keys list")  # noqa: TRY004
    doc = snapshot.get("doc")
    did = doc.get("id") if isinstance(doc, dict) else None
    did = did if isinstance(did, str) else None
    table: dict[str, dict[str, Any]] = {}
    for entry in snapshot["keys"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("kid"), str):
            continue
        kid = entry["kid"]
        if kid.startswith("#") and did is not None:
            kid = did + kid
        if did is not None and kid.split("#", 1)[0] != did:
            continue
        kind = entry.get("type")
        slot = _KEY_SLOTS.get(kind) if isinstance(kind, str) else None
        public = _key_bytes(entry)
        revoked = entry.get("revokedAtMs")
        if slot is None or public is None or not (revoked is None or _uint(revoked)):
            continue
        row = table.setdefault(kid, {"ed": None, "x": None, "revoked": None})
        if row[slot] is not None:
            raise ValueError(f"DID snapshot lists {kid} twice")
        row[slot] = public
        if revoked is not None:
            row["revoked"] = revoked if row["revoked"] is None else min(row["revoked"], revoked)

    def resolve(kid: str) -> KeyInfo | None:
        row = table.get(kid) if isinstance(kid, str) else None
        if row is None:
            return None
        return KeyInfo(kid, row["ed"], row["x"], row["revoked"])

    return resolve


# ---------------------------------------------------------------- parsing helpers


def _obj(v: Any, what: str) -> dict:
    if not isinstance(v, dict):
        raise _Fail(f"{what} is missing or not an object")
    return v


def _hex(v: Any, what: str, size: int | None = None) -> bytes:
    if not isinstance(v, str):
        raise _Fail(f"{what} is missing or not a hex string")
    try:
        raw = from_hex(v)
    except ValueError:
        raise _Fail(f"{what} is not valid hex") from None
    if size is not None and len(raw) != size:
        raise _Fail(f"{what} must be {size} bytes")
    return raw


def _path(v: Any, what: str) -> list[merkle.PathStep]:
    if not isinstance(v, list):
        raise _Fail(f"{what} is missing or not a list")
    steps = []
    for i, s in enumerate(v):
        s = _obj(s, f"{what}[{i}]")
        side = s.get("side")
        if side not in ("L", "R"):
            raise _Fail(f"{what}[{i}].side must be L or R")
        steps.append(merkle.PathStep(side, _hex(s.get("hash"), f"{what}[{i}].hash", 32)))
    return steps


def _block_raw(b: dict) -> bytes:
    return _hex(_obj(b.get("block"), "block").get("raw"), "block.raw")


def _block_id(b: dict) -> bytes:
    return _hex(_obj(b.get("block"), "block").get("id"), "block.id", 32)


def _essence(b: dict) -> tuple[bytes, MilestoneEssence]:
    ms = _obj(b.get("milestone"), "milestone")
    essence_bytes = _hex(ms.get("essence"), "milestone.essence")
    try:
        return essence_bytes, _parse_essence(essence_bytes)
    except codec.DecodeError as exc:
        raise _Fail(f"milestone essence does not parse: {exc}") from None


def _uint(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= _MAX_INT


def _json(data: bytes) -> Any:
    def reject(token: str) -> Any:
        raise ValueError(f"non-finite number {token}")

    try:
        return json.loads(data.decode("utf-8"), parse_constant=reject)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None


# ---------------------------------------------------------------- steps


def _step_block_hash(b: dict) -> tuple[bool | None, str]:
    raw = _block_raw(b)
    claimed = _block_id(b)
    actual = blake2b256(raw)
    if actual != claimed:
        return False, f"BLAKE2b-256(raw) is {to_hex(actual)}, bundle claims {to_hex(claimed)}"
    try:
        codec.parse_block(raw)
    except codec.DecodeError as exc:
        return False, f"block does not parse: {exc}"
    return True, f"BLAKE2b-256(raw) = {to_hex(actual)}"


def _step_inclusion(b: dict) -> tuple[bool | None, str]:
    bid = _block_id(b)
    _, essence = _essence(b)
    path = _path(_obj(b.get("inclusion"), "inclusion").get("path"), "inclusion.path")
    root = essence.inclusion_merkle_root
    if merkle.verify(bid, path, root):
        return True, f"{len(path)}-step path reaches inclusionMerkleRoot {to_hex(root)}"
    return False, f"Merkle path does not reach inclusionMerkleRoot {to_hex(root)}"


def _step_signatures(b: dict, cfg: VerifierConfig) -> tuple[bool | None, str]:
    threshold = cfg.threshold
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        return False, "verifier threshold must be at least 1"
    essence_bytes, essence = _essence(b)
    ms = _obj(b.get("milestone"), "milestone")
    mid = codec.milestone_id(essence_bytes)
    if "id" in ms and _hex(ms["id"], "milestone.id", 32) != mid:
        return False, f"milestone.id does not match BLAKE2b-256(essence) = {to_hex(mid)}"
    if "index" in ms and not (_uint(ms["index"]) and ms["index"] == essence.index):
        return False, f"milestone.index does not match the essence index {essence.index}"
    sigs = ms.get("signatures")
    if not isinstance(sigs, list):
        raise _Fail("milestone.signatures is missing or not a list")
    valid: set[bytes] = set()
    for entry in sigs:
        if not isinstance(entry, dict):
            continue
        try:
            pk = _hex(entry.get("pk"), "pk", codec.PUBKEY_LEN)
            sig = _hex(entry.get("sig"), "sig", codec.SIG_LEN)
        except _Fail:
            continue
        if pk not in cfg.trusted_coordinator_keys or pk in valid:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(pk).verify(sig, mid)
        except (InvalidSignature, ValueError):
            continue
        valid.add(pk)
    summary = f"{len(valid)} valid signature(s) by pinned keys, threshold {threshold}"
    return len(valid) >= threshold, f"milestone {essence.index} {to_hex(mid)}: {summary}"


UNRESOLVED_SIGNER = "signer identity not resolved (bundle snapshot is unauthenticated)"


def _trusted_keys(
    resolve_did: Callable[[str], dict | None] | None, iss: str
) -> Callable[[str], KeyInfo | None] | None:
    """Keys of `iss` from the trusted resolver; None if it cannot be resolved."""
    if resolve_did is None:
        return None
    try:
        resolved = resolve_did(iss)
    except Exception:  # noqa: BLE001 - an unreachable registry is not a verdict
        return None
    if resolved is None:
        return None
    doc = resolved.get("doc") if isinstance(resolved, dict) else None
    if not isinstance(doc, dict) or doc.get("id") != iss:
        raise _Fail("resolved DID document does not belong to the issuer")
    try:
        return snapshot_resolver(resolved)
    except ValueError as exc:
        raise _Fail(f"resolved DID document is malformed: {exc}") from None


def _snapshot_matches(b: dict, kid: str, trusted: KeyInfo) -> None:
    """The bundle's snapshot is display-only, but it must not contradict the registry."""
    section = b.get("envelope")
    snapshot = section.get("didDoc") if isinstance(section, dict) else None
    if snapshot is None:
        return
    try:
        claimed = snapshot_resolver(snapshot)(kid)
    except ValueError:
        claimed = None
    if claimed is None or claimed.ed25519_public != trusted.ed25519_public:
        raise _Fail("DID snapshot does not match resolved document")


def _step_envelope(
    b: dict, resolve_did: Callable[[str], dict | None] | None
) -> tuple[bool | None, str]:
    try:
        raw = _block_raw(b)
        block = codec.parse_block(raw)
    except (_Fail, codec.DecodeError):
        raise _Skip("not evaluated: block does not parse") from None
    payload = block.payload
    if not isinstance(payload, codec.TaggedData):
        return None, "block carries no tagged data"
    env = _json(payload.data)
    if not envelope.is_envelope(env):
        return None, "unsigned legacy message"
    try:
        tag = payload.tag.decode("utf-8")
    except UnicodeDecodeError:
        return False, f"{verdicts.FORGED}: block tag is not UTF-8"
    # Structure, tag binding and kid/iss binding do not depend on any key.
    offline = envelope.verify(env, tag, lambda _kid: None)
    if offline.verdict == verdicts.MALFORMED:
        return False, f"{offline.verdict}: {offline.reason}"
    iss, kid = env["iss"], env["kid"]
    if env["tag"] != tag or kid.split("#", 1)[0] != iss:
        return False, f"{offline.verdict}: {offline.reason}"
    # Signer keys come only from the trusted resolver, never from the bundle.
    trusted = _trusted_keys(resolve_did, iss)
    if trusted is None:
        return None, UNRESOLVED_SIGNER
    check = envelope.verify(env, tag, trusted)
    if check.verdict not in (verdicts.PRODUCER_SIGNED, verdicts.RELAY_ATTESTED):
        return False, f"{check.verdict}: {check.reason}"
    info = trusted(kid)
    if info is None:  # unreachable: verify() just resolved it
        return False, "signing key not resolvable"
    _snapshot_matches(b, kid, info)
    if info.revoked_at_ms is not None:
        try:
            _, essence = _essence(b)
        except _Fail:
            return False, "key revoked; inclusion time unknown"
        if essence.timestamp * 1000 > info.revoked_at_ms:
            return False, "key revoked before inclusion"
    return True, f"{check.verdict} by {kid}"


def _record_matches(record: Any, expected: bytes) -> tuple[bool, str]:
    if not isinstance(record, dict) or not ({"checkpointHash", "checkpoint"} & record.keys()):
        return False, "anchor record malformed"
    if "checkpointHash" in record:
        try:
            onchain = _hex(record["checkpointHash"], "record.checkpointHash", 32)
        except _Fail:
            return False, "anchor record malformed"
        if onchain != expected:
            return False, "checkpoint does not match on-chain record"
    if "checkpoint" in record:
        try:
            onchain = checkpoint.hash(record["checkpoint"])
        except Exception:  # noqa: BLE001 - JCS rejects NaN, huge ints, ...
            return False, "anchor record malformed"
        if onchain != expected:
            return False, "checkpoint does not match on-chain record"
    return True, f"checkpoint {to_hex(expected)} matches the on-chain record"


def _step_anchor(
    b: dict, cfg: VerifierConfig, fetch: Callable[[dict], dict | None] | None
) -> tuple[bool | None, str]:
    if b.get("anchor") is None:
        return None, "bundle carries no anchor"
    if fetch is None:
        return None, "anchor not checked: no record fetcher"
    anchor = _obj(b["anchor"], "anchor")
    cp = anchor.get("checkpoint")
    problem = checkpoint.shape_error(cp)
    if problem is not None:
        return False, f"malformed checkpoint: {problem}"
    if not (cp["network"] == b.get("network") == cfg.network):
        return False, (
            f"checkpoint network {cp['network']!r} does not match bundle "
            f"{b.get('network')!r} / pinned {cfg.network!r}"
        )
    essence_bytes, essence = _essence(b)
    mid = codec.milestone_id(essence_bytes)
    path = _path(anchor.get("msPath"), "anchor.msPath")
    in_range = cp["from"]["index"] <= essence.index <= cp["to"]["index"]
    if not (in_range and merkle.verify(mid, path, from_hex(cp["msRoot"]))):
        return False, "milestone not in anchored checkpoint"
    rebased = _obj(anchor.get("rebased"), "anchor.rebased")
    if cfg.trail_id is None:
        return None, "anchor not checked: verifier pins no Rebased trail"
    if rebased.get("trail") != cfg.trail_id:
        return False, "anchor trail is not the pinned trail"
    if cfg.rebased_network is not None and rebased.get("network") != cfg.rebased_network:
        return False, "anchor is not on the pinned Rebased network"
    try:
        record = fetch(anchor)
    except Exception as exc:  # noqa: BLE001 - an unreachable chain is not a verdict
        return None, f"anchor record unavailable ({type(exc).__name__})"
    if record is None:
        return None, "anchor record unavailable"
    return _record_matches(record, checkpoint.hash(cp))


# ---------------------------------------------------------------- ladder


def _run(name: StepName, fn: Callable[..., tuple[bool | None, str]], *args: Any) -> StepResult:
    try:
        ok, detail = fn(*args)
    except _Fail as exc:
        ok, detail = False, str(exc)
    except _Skip as exc:
        ok, detail = None, str(exc)
    except Exception as exc:  # noqa: BLE001 - hostile input must never escape as an exception
        ok, detail = False, f"malformed bundle ({type(exc).__name__})"
    return StepResult(name, ok, detail)


def _overall(steps: list[StepResult]) -> Overall:
    if any(s.ok is False for s in steps):
        return "INVALID"
    if all(s.ok is True for s in steps):
        return "VALID"
    return "PARTIAL"


def verify(
    b: dict,
    cfg: VerifierConfig,
    fetch_anchor_record: Callable[[dict], dict | None] | None = None,
    resolve_did: Callable[[str], dict | None] | None = None,
) -> Ladder:
    """Run the five-step ladder. Never raises on bad input.

    `fetch_anchor_record` reads the on-chain checkpoint record for step 5;
    `resolve_did` returns the issuer's DID document from the trusted registry
    (`{"doc", "version", "keys"}`) for step 4. Without them those steps stay
    unevaluated (None): the bundle's own snapshot never authenticates a signer.
    """
    if not isinstance(b, dict) or not _uint(b.get("v")) or b.get("v") != VERSION:
        reason = "not a witness-proof/v1 bundle"
        steps = [StepResult(n, False, reason) for n in STEP_NAMES]
        return Ladder(steps, "INVALID")
    steps = [
        _run("block_hash", _step_block_hash, b),
        _run("inclusion", _step_inclusion, b),
        _run("milestone_signatures", _step_signatures, b, cfg),
        _run("envelope", _step_envelope, b, resolve_did),
        _run("anchor", _step_anchor, b, cfg, fetch_anchor_record),
    ]
    return Ladder(steps, _overall(steps))
