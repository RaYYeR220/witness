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

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from . import checkpoint, codec, ed25519, envelope, merkle, nesting, verdicts
from .codec import Ed25519Sig, MilestoneEssence
from .envelope import EnvelopeCheck, KeyInfo
from .ids import NON_CANONICAL_DID, blake2b256, from_hex, is_canonical_did, to_hex

StepName = Literal["block_hash", "inclusion", "milestone_signatures", "envelope", "anchor"]
Overall = Literal["VALID", "INVALID", "PARTIAL"]
STEP_NAMES: tuple[StepName, ...] = (
    "block_hash", "inclusion", "milestone_signatures", "envelope", "anchor",
)
VERSION = 1
_MAX_INT = 2**53 - 1
_CANON_HEX = re.compile(r"0x(?:[0-9a-f]{2})*")
_KEY_SLOTS = {"Ed25519": "ed", "X25519": "x"}


@dataclass(frozen=True)
class VerifierConfig:
    """What the verifier pins out of band; everything else comes from the bundle."""

    network: str
    trusted_coordinator_keys: set[bytes]
    threshold: int
    rebased_network: str | None = None
    trail_id: str | None = None
    # Where and what to read the anchor record from (see `rebased.make_fetcher`).
    rebased_rpc: str | None = None
    audit_trail_package: str | None = None
    # Address that wrote the anchor's trail records; when pinned, other writers fail step 5.
    anchor_writer: str | None = None


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


class KeyLookup(Protocol):
    """`kid` -> key, optionally as it stood at `at_ms` (epoch ms)."""

    def __call__(self, kid: str, at_ms: int | None = None) -> KeyInfo | None: ...


def snapshot_keys(snapshot: dict) -> dict[str, list[KeyInfo]]:
    """Every key entry of a DID snapshot in the anchor service's resolve shape, per kid.

    `{"doc": {"id": did, ...}, "version": ..., "keys": [{"kid", "type", "publicKeyHex",
    "revokedAtMs"}]}`. The list covers the key history: a kid whose key was replaced in
    place appears once per key, each entry carrying its own revocation time (None while
    current), in the order the snapshot lists them. Fragment kids (`#sig-1`) are expanded
    against `doc.id`; entries that name another DID are ignored. Fails closed: a kid with
    any entry that cannot be read (unknown type, bad key, bad revocation time) is left out
    entirely, since which of its keys was in force when can no longer be told. Raises
    ValueError if the snapshot is not usable at all.
    """
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("keys"), list):
        raise ValueError("DID snapshot must be an object with a keys list")  # noqa: TRY004
    doc = snapshot.get("doc")
    did = doc.get("id") if isinstance(doc, dict) else None
    did = did if isinstance(did, str) else None
    table: dict[str, list[KeyInfo]] = {}
    unreadable: set[str] = set()
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
            unreadable.add(kid)
            continue
        ed, x = (public, None) if slot == "ed" else (None, public)
        table.setdefault(kid, []).append(KeyInfo(kid, ed, x, revoked))
    return {kid: keys for kid, keys in table.items() if kid not in unreadable}


def second_end_ms(ts_s: int) -> int:
    """First millisecond after the second `ts_s` (a milestone timestamp, in seconds)."""
    return (ts_s + 1) * 1000


def valid_through_second(revoked_at_ms: int | None, ts_s: int) -> bool:
    """Whether a key revoked at `revoked_at_ms` may sign a message confirmed by a milestone
    with timestamp `ts_s`.

    Milestone timestamps have second precision, so the inclusion instant is only known to
    lie somewhere inside that second. Fail closed: a revocation anywhere in the second, or
    before it, revokes. The key is valid only if never revoked or revoked at or after the
    end of the second.
    """
    return revoked_at_ms is None or revoked_at_ms >= second_end_ms(ts_s)


def _in_force(keys: list[KeyInfo], at_ms: int | None) -> KeyInfo | None:
    """The key in force at `at_ms`, or the current one when `at_ms` is None.

    A key is valid at `at_ms` while it is not revoked or revoked at or after `at_ms` (a
    message is revoked only when included strictly after the revocation). A replaced key
    was revoked when its successor took over, so among the valid ones the key that expires
    first is the one that was in force; ties go to the entry listed last. With nothing valid
    the key revoked last is returned, so the caller sees the revocation instead of nothing.
    """
    if not keys:
        return None

    def expiry(k: KeyInfo) -> float:
        return float("inf") if k.revoked_at_ms is None else k.revoked_at_ms

    if at_ms is None:
        valid = [k for k in keys if k.revoked_at_ms is None]
    else:
        valid = [k for k in keys if k.revoked_at_ms is None or k.revoked_at_ms >= at_ms]
    if valid:
        return min(reversed(valid), key=expiry)
    return max(reversed(keys), key=expiry)


def snapshot_resolver(snapshot: dict) -> KeyLookup:
    """Key lookup over a DID snapshot (see `snapshot_keys`), time-aware for replaced keys.

    `resolve(kid)` serves the current key; `resolve(kid, at_ms)` the key in force at that
    time. A kid listing both an Ed25519 and an X25519 key gets both, each chosen by time;
    `revoked_at_ms` is the earlier revocation of the two chosen keys.
    """
    table = snapshot_keys(snapshot)

    def resolve(kid: str, at_ms: int | None = None) -> KeyInfo | None:
        keys = table.get(kid) if isinstance(kid, str) else None
        if not keys:
            return None
        ed = _in_force([k for k in keys if k.ed25519_public is not None], at_ms)
        x = _in_force([k for k in keys if k.x25519_public is not None], at_ms)
        revoked = [k.revoked_at_ms for k in (ed, x) if k is not None and k.revoked_at_ms is not None]
        return KeyInfo(
            kid,
            None if ed is None else ed.ed25519_public,
            None if x is None else x.x25519_public,
            min(revoked) if revoked else None,
        )

    return resolve


# ---------------------------------------------------------------- parsing helpers


def _obj(v: Any, what: str) -> dict:
    if not isinstance(v, dict):
        raise _Fail(f"{what} is missing or not an object")
    return v


def _hex(v: Any, what: str, size: int | None = None) -> bytes:
    """Decode strict lowercase 0x-hex; anything a canonical builder would not emit fails."""
    if not isinstance(v, str):
        raise _Fail(f"{what} is missing or not a hex string")
    if not _CANON_HEX.fullmatch(v):
        try:
            from_hex(v)
        except ValueError:
            raise _Fail(f"{what} is not valid hex") from None
        raise _Fail(f"{what}: non-canonical hex (expected lowercase with 0x prefix)")
    raw = bytes.fromhex(v[2:])
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
    """Tagged-data JSON; None only when the bytes are not UTF-8 or not JSON.

    Text nesting deeper than `nesting.MAX_JSON_DEPTH` raises RecursionError, valid JSON or
    not, so the step fails closed: where json.loads itself gives up depends on the
    platform, and "unsigned legacy" (not evaluated) on one verifier against a failure on
    another would split the verdict. `nesting.loads` turns a RecursionError from json.loads
    (it cannot happen below the cap) into the same.
    """

    def reject(token: str) -> Any:
        raise ValueError(f"non-finite number {token}")

    try:
        return nesting.loads(data.decode("utf-8"), parse_constant=reject)
    except nesting.JsonTooDeep as exc:
        raise RecursionError(str(exc)) from None
    except ValueError:  # includes UnicodeDecodeError
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
    if b.get("network") != cfg.network:
        # Coordinator keys are pinned for one network; a foreign label is a foreign milestone.
        return False, f"bundle network {b.get('network')!r} is not the pinned {cfg.network!r}"
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
    for i, entry in enumerate(sigs):
        entry = _obj(entry, f"milestone.signatures[{i}]")
        pk = _hex(entry.get("pk"), f"milestone.signatures[{i}].pk", codec.PUBKEY_LEN)
        sig = _hex(entry.get("sig"), f"milestone.signatures[{i}].sig", codec.SIG_LEN)
        if pk not in cfg.trusted_coordinator_keys or pk in valid:
            continue
        # A pinned key of small order would accept a forged signature: never counted.
        if ed25519.verify(pk, sig, mid):
            valid.add(pk)
    summary = f"{len(valid)} valid signature(s) by pinned keys, threshold {threshold}"
    return len(valid) >= threshold, f"milestone {essence.index} {to_hex(mid)}: {summary}"


UNRESOLVED_SIGNER = "signer identity not resolved (bundle snapshot is unauthenticated)"


def _trusted_keys(
    resolve_did: Callable[[str], dict | None] | None, iss: str
) -> KeyLookup | None:
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


def _snapshot_matches(b: dict, kid: str, trusted: KeyInfo, at_ms: int | None) -> None:
    """The bundle's snapshot is display-only, but it must not contradict the registry."""
    section = b.get("envelope")
    snapshot = section.get("didDoc") if isinstance(section, dict) else None
    if snapshot is None:
        return
    try:
        claimed = snapshot_resolver(snapshot)(kid, at_ms)
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
    # A did:iota DID in any other spelling is never looked up (the registry would answer
    # for the canonical one): FORGED, as the indexer and the relay judge it.
    if not is_canonical_did(iss):
        return False, f"{verdicts.FORGED}: {NON_CANONICAL_DID}"
    # Signer keys come only from the trusted resolver, never from the bundle.
    trusted = _trusted_keys(resolve_did, iss)
    if trusted is None:
        return None, UNRESOLVED_SIGNER
    # A key replaced in place has several entries; use the one in force through the whole
    # inclusion second (milestone timestamps have second precision).
    try:
        ts: int | None = _essence(b)[1].timestamp
    except _Fail:
        ts = None
    at_ms = None if ts is None else second_end_ms(ts)
    check = envelope.verify(env, tag, lambda k: trusted(k, at_ms))
    if check.verdict not in (verdicts.PRODUCER_SIGNED, verdicts.RELAY_ATTESTED):
        return False, f"{check.verdict}: {check.reason}"
    info = trusted(kid, at_ms)
    if info is None:  # unreachable: verify() just resolved it
        return False, "signing key not resolvable"
    _snapshot_matches(b, kid, info, at_ms)
    if info.revoked_at_ms is not None:
        if ts is None:
            return False, "key revoked; inclusion time unknown"
        if info.revoked_at_ms < ts * 1000:
            return False, "key revoked before inclusion"
        if not valid_through_second(info.revoked_at_ms, ts):
            return False, "key revoked within the inclusion second"
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
    if not _uint(rebased.get("record")):
        return False, "anchor.rebased.record must be an unsigned integer"
    if cfg.trail_id is None or cfg.rebased_network is None:
        return None, "anchor not checked: verifier pins no Rebased trail"
    if rebased.get("trail") != cfg.trail_id:
        return False, "anchor trail is not the pinned trail"
    if rebased.get("network") != cfg.rebased_network:
        return False, "anchor is not on the pinned Rebased network"
    if fetch is None:
        return None, "anchor not checked: no record fetcher"
    try:
        record = fetch(anchor)
    except Exception as exc:  # noqa: BLE001 - an unreachable chain is not a verdict
        return None, f"anchor record unavailable ({type(exc).__name__})"
    if record is None:
        return None, "anchor record unavailable"
    if cfg.anchor_writer is not None and (
        not isinstance(record, dict) or record.get("addedBy") != cfg.anchor_writer
    ):
        return False, "anchor record was not written by the pinned anchor writer"
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


def served_block_id(b: Any) -> str | None:
    """The block id a fetched bundle claims, lowercase, or None if it names none.

    Step ① ties this id to the raw bytes, but nothing in the ladder ties it to the block the
    caller asked for: a caller that fetched a bundle by id must compare the two itself, or an
    API could answer with the valid proof of some other block.
    """
    block = b.get("block") if isinstance(b, dict) else None
    bid = block.get("id") if isinstance(block, dict) else None
    return bid.lower() if isinstance(bid, str) else None


def verify(
    b: dict,
    cfg: VerifierConfig,
    fetch_anchor_record: Callable[[dict], dict | None] | None = None,
    resolve_did: Callable[[str], dict | None] | None = None,
) -> Ladder:
    """Run the five-step ladder. Never raises on bad input.

    `fetch_anchor_record(anchor)` returns the on-chain checkpoint record for
    step 5 (`{"checkpointHash"}` and/or `{"checkpoint"}`, None if unreachable).
    It must read record `anchor["rebased"]["record"]` from the verifier's pinned
    trail on the pinned Rebased network (`cfg.trail_id`, `cfg.rebased_network`)
    and ignore the bundle's `tx` and `network`. It is only called once the
    checkpoint, membership path and pins have been checked locally.

    `resolve_did(did)` returns the issuer's DID document from the trusted
    registry (`{"doc", "version", "keys"}`) for step 4.

    Without them steps 4 and 5 can be at best unevaluated (None): the bundle's
    own snapshot never authenticates a signer, and an anchor is never confirmed
    without the on-chain record. Local contradictions are red either way.
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
