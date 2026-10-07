"""The twenty attacks of the answer key, one function each, and the positive control.

Every attack is `async def aNN_*(ctx) -> InjectionRecord`. The `build_*` helpers hold
the exact bytes, requests and SQL an attack sends and are pure, so tests can check
them without any service. Offline attacks (A07-A10) run completely here; the others
refuse to send anything unless `ctx.live is True`, which only the runner sets.
`CONTROLS` maps the answer key's controls (C01) to their injectors.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from witness_core import bundle, canon, codec, envelope, sealed
from witness_core.bundle import VerifierConfig
from witness_core.ids import blake2b256, from_hex, to_hex

from . import forge

TRUST_TAG = "trust.score"
SEALED_TAG = "audit.report"
FOREIGN_TAG = "LLO-K8s"
HORNET_BLOCKS = "/api/core/v2/blocks"
ORION_ENTITIES = "/ngsi-ld/v1/entities"
IE_URN = "urn:ngsi-ld:InfrastructureElement:"


class LiveDisabled(RuntimeError):
    """An attack that sends traffic was called while `ctx.live` is not True."""


@dataclass(frozen=True)
class Identity:
    """A signing identity: DID, key id and the private key."""

    iss: str
    kid: str
    key: Ed25519PrivateKey


@dataclass
class AttackContext:
    # Endpoints.
    hornet_url: str = "http://127.0.0.1:14265"
    relay_url: str = "http://127.0.0.1:5557"
    relay_node: str = "default"
    relay_token: str | None = None
    ingest_url: str = "http://127.0.0.1:8000/ingest"
    ingest_token: str | None = None
    # Forged submission records (A16, A18) travel the way the relay forwards real ones:
    # "http" (POST /ingest), "mqtt" (aerios/iota/submissions/{tag}) or "both".
    ingest_via: str = "http"
    mqtt_url: str | None = None
    mqtt_publish: Callable[[str, bytes], Awaitable[None]] | None = None
    orion_url: str = "http://127.0.0.1:1026"
    db_dsn: str | None = None
    # Identities of the run.
    producer: Identity | None = None  # allowed on trust.score
    outsider: Identity | None = None  # resolvable, not in the policy
    revoked: Identity | None = None  # key revoked before the run
    attacker_key: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)
    # Infrastructure Elements the run may write about.
    ie_id: str = "ChaosDomain:aabbccddeeff"
    stale_ie_id: str = "ChaosDomain:112233445566"
    baseline_score: float = 0.5
    # Per-trial IE ids come from these pools (IEs the run registered in Orion); when a
    # pool is empty a fresh random id is used.
    ie_pool: list[str] = field(default_factory=list)
    stale_pool: list[str] = field(default_factory=list)
    search_key: bytes | None = None  # domain blind-index key, for A11
    # Offline classes.
    real_bundle: dict | None = None
    sample_private_keys: list[bytes] = field(default_factory=list)
    verifier: VerifierConfig | None = None
    anchor_fetch: Callable[[dict], dict | None] | None = None
    # Plumbing.
    http: httpx.AsyncClient | None = None
    rng: random.Random = field(default_factory=random.Random)
    clock_ms: Callable[[], int] = field(default=lambda: int(time.time() * 1000))
    live: bool = False
    # Called at the end of every begin_trial (the runner sets the trial IEs' trustScore in
    # Orion there, as the Trust Manager would). Synchronous: it runs inside the attack.
    on_trial: Callable[[AttackContext], None] | None = None
    # Two-block attacks (A03, A13, A20) are about order: the second block must come after
    # the first. When set, they await this with the first block's id before sending the
    # second; the runner waits there until the explorer has indexed it, since two blocks
    # in one milestone are otherwise processed in white-flag order, not sending order.
    wait_indexed: Callable[[str], Awaitable[None]] | None = None
    # Block ids A19 rewrote in this run, with the bytes they held before (the runner puts
    # them back at the end). Each one is also appended to `tamper_log` before the rewrite,
    # so an interrupted run can still be restored with `witness-chaos restore`.
    tampered: list[bytes] = field(default_factory=list)
    originals: dict[bytes, bytes] = field(default_factory=dict)
    tamper_log: Path | None = None
    _seq: dict[str, int] = field(default_factory=dict, repr=False)

    def next_seq(self, iss: str) -> int:
        """Strictly increasing per issuer and never behind the clock (epoch ms), so it stays
        above any seq an earlier run or a signer that jumped to the time has used."""
        self._seq[iss] = max(self.clock_ms(), self._seq.get(iss, 0) + 1)
        return self._seq[iss]

    def begin_trial(self) -> None:
        """Fresh IE ids and baseline score, so trials cannot interfere with each other."""
        self.ie_id = self.ie_pool.pop(0) if self.ie_pool else random_ie_id(self.rng)
        self.stale_ie_id = (self.stale_pool.pop(0) if self.stale_pool
                            else random_ie_id(self.rng))
        self.baseline_score = round(self.rng.uniform(0.4, 0.6), 3)
        if self.on_trial is not None:
            self.on_trial(self)

    def require_live(self) -> None:
        if self.live is not True:
            raise LiveDisabled("this attack sends traffic; the runner must set ctx.live = True")

    def need(self, name: str) -> Any:
        value = getattr(self, name)
        if value is None:
            raise ValueError(f"AttackContext.{name} is required for this attack")
        return value


@dataclass(frozen=True)
class InjectionRecord:
    id: str
    block_id: str | None
    ie_id: str | None
    expected: dict
    injected_at_ms: int
    detail: dict


def answer_key() -> dict:
    text = resources.files("witness_chaos").joinpath("answer_key.yaml").read_text("utf-8")
    return yaml.safe_load(text)


def expected_for(class_id: str) -> dict:
    key = answer_key()
    for c in [*key["classes"], *key.get("controls", [])]:
        if c["id"] == class_id:
            return dict(c["expect"])
    raise KeyError(class_id)


def _record(ctx: AttackContext, cid: str, block_id: str | None, ie_id: str | None,
            detail: dict, at_ms: int | None = None) -> InjectionRecord:
    return InjectionRecord(cid, block_id, ie_id, expected_for(cid),
                           ctx.clock_ms() if at_ms is None else at_ms, detail)


# ------------------------------------------------------------------ builders: envelopes


def score_body(ie_id: str, score: float) -> dict:
    return {"id": ie_id, "score": score}


def seal_as(ident: Identity, ctx: AttackContext, body: dict, *, tag: str = TRUST_TAG,
            seq: int | None = None, sign_key: Ed25519PrivateKey | None = None,
            prev: str | None = None) -> dict:
    return envelope.seal(
        tag, body, iss=ident.iss, kid=ident.kid, sign_key=sign_key or ident.key,
        seq=ctx.next_seq(ident.iss) if seq is None else seq, att_mode="producer",
        now_ms=ctx.clock_ms(), prev=prev)


def env_bytes(env: dict) -> bytes:
    return canon.jcs(env)


def hornet_request(tag: str, data: bytes) -> tuple[str, dict]:
    """Path and JSON body of a direct tagged-data submission to HORNET."""
    return HORNET_BLOCKS, {
        "protocolVersion": 2,
        "payload": {"type": 5, "tag": "0x" + tag.encode().hex(), "data": "0x" + data.hex()},
    }


def build_a01(ctx: AttackContext) -> tuple[str, bytes]:
    """Trust-manager iss/kid, signature made with the attacker's key."""
    p = ctx.need("producer")
    env = seal_as(p, ctx, score_body(ctx.ie_id, ctx.baseline_score), sign_key=ctx.attacker_key)
    return TRUST_TAG, env_bytes(env)


def build_a02(ctx: AttackContext) -> tuple[str, bytes]:
    """A valid trust.score envelope, published under another block tag."""
    p = ctx.need("producer")
    env = seal_as(p, ctx, score_body(ctx.ie_id, ctx.baseline_score))
    return FOREIGN_TAG, env_bytes(env)


def build_a03(ctx: AttackContext) -> tuple[tuple[str, bytes], tuple[str, bytes]]:
    """(original, replay): same (iss, seq), different nonce and bytes."""
    p = ctx.need("producer")
    seq = ctx.next_seq(p.iss)
    body = score_body(ctx.ie_id, ctx.baseline_score)
    first = seal_as(p, ctx, body, seq=seq)
    again = seal_as(p, ctx, body, seq=seq)
    return (TRUST_TAG, env_bytes(first)), (TRUST_TAG, env_bytes(again))


def build_a04(ctx: AttackContext) -> tuple[str, bytes]:
    o = ctx.need("outsider")
    return TRUST_TAG, env_bytes(seal_as(o, ctx, score_body(ctx.ie_id, ctx.baseline_score)))


def build_a05(ctx: AttackContext) -> tuple[str, bytes]:
    r = ctx.need("revoked")
    return TRUST_TAG, env_bytes(seal_as(r, ctx, score_body(ctx.ie_id, ctx.baseline_score)))


def random_ie_id(rng: random.Random, domain: str = "ChaosDomain") -> str:
    return f"{domain}:{rng.getrandbits(48):012x}"


def build_a12(ctx: AttackContext) -> tuple[str, bytes, str]:
    """Signed score about an IE Orion does not have. Returns (tag, data, ie_id)."""
    p = ctx.need("producer")
    ie = random_ie_id(ctx.rng)
    return TRUST_TAG, env_bytes(seal_as(p, ctx, score_body(ie, 0.5))), ie


def build_a13(ctx: AttackContext) -> list[tuple[str, bytes]]:
    """Two scores for one IE, 0.9 then 0.1: a jump of 0.8 with no security event."""
    p = ctx.need("producer")
    return [(TRUST_TAG, env_bytes(seal_as(p, ctx, score_body(ctx.ie_id, s))))
            for s in (0.9, 0.1)]


def build_a14(ctx: AttackContext) -> tuple[str, bytes]:
    p = ctx.need("producer")
    return TRUST_TAG, env_bytes(seal_as(p, ctx, score_body(ctx.stale_ie_id, 0.5)))


def build_a15(ctx: AttackContext) -> tuple[str, bytes]:
    """Validly signed, schema-breaking body: score out of range, id not an IE id."""
    p = ctx.need("producer")
    return TRUST_TAG, env_bytes(seal_as(p, ctx, {"id": "not-an-ie-id", "score": 7}))


def build_a17(ctx: AttackContext) -> tuple[str, bytes]:
    """A fully valid score, posted to HORNET so no submission record exists for it."""
    p = ctx.need("producer")
    return TRUST_TAG, env_bytes(seal_as(p, ctx, score_body(ctx.ie_id, ctx.baseline_score)))


def build_a20(ctx: AttackContext) -> tuple[dict, dict, str]:
    """(m1, m3, missing_prev): m3's `prev` names the block of a dropped m2.

    m2 is never sent, so the id in `prev` belongs to no block on the Tangle.
    """
    p = ctx.need("producer")
    seq = ctx.next_seq(p.iss)
    m1 = seal_as(p, ctx, score_body(ctx.ie_id, ctx.baseline_score), seq=seq)
    m2 = seal_as(p, ctx, score_body(ctx.ie_id, ctx.baseline_score), seq=ctx.next_seq(p.iss))
    missing = to_hex(blake2b256(env_bytes(m2)))
    m3 = seal_as(p, ctx, score_body(ctx.ie_id, ctx.baseline_score),
                 seq=ctx.next_seq(p.iss), prev=missing)
    return m1, m3, missing


# ------------------------------------------------------------------ builders: relay/ingest/orion/db


def relay_upload(ctx: AttackContext, tag: str, message: Any) -> tuple[str, dict, dict]:
    """URL, JSON body and headers of a Messages API upload."""
    headers = {"Content-Type": "application/json"}
    if ctx.relay_token:
        headers["Authorization"] = f"Bearer {ctx.relay_token}"
    return (f"{ctx.relay_url.rstrip('/')}/upload?node={ctx.relay_node}",
            {"tag": tag, "message": message}, headers)


def submission_record(tag: str, message: Any, data: bytes | None, block_id: str | None,
                      *, now_ms: int, hornet_status: int | None = 201) -> dict:
    """A relay submission record in the format `/ingest` and MQTT carry."""
    return {
        "subId": str(uuid.uuid4()),
        "receivedAtMs": now_ms,
        "tag": tag,
        "message": message,
        "dataHex": None if data is None else "0x" + data.hex(),
        "blockId": block_id,
        "hornetStatus": hornet_status,
        "relay": {"verdict": None, "iss": None, "seq": None},
    }


def build_a16_record(block_id: str, tag: str, sent: bytes, now_ms: int) -> dict:
    """Record for a real block whose `dataHex` is not what is on the Tangle."""
    altered = bytearray(sent)
    altered[len(altered) // 2] ^= 0x01
    return submission_record(tag, json.loads(sent), bytes(altered), block_id, now_ms=now_ms)


def build_a18_record(ctx: AttackContext) -> dict:
    """Record naming a block id that was never created."""
    data = env_bytes(seal_as(ctx.need("producer"), ctx,
                             score_body(ctx.ie_id, ctx.baseline_score)))
    ghost = to_hex(ctx.rng.randbytes(32))
    return submission_record(TRUST_TAG, json.loads(data), data, ghost, now_ms=ctx.clock_ms())


def orion_patch(ctx: AttackContext, ie_id: str, ledger_score: float) -> tuple[str, dict]:
    """URL and body overwriting trustScore with a value far from the ledger's."""
    wrong = 0.05 if ledger_score > 0.5 else 0.95
    url = f"{ctx.orion_url.rstrip('/')}{ORION_ENTITIES}/{IE_URN}{ie_id}/attrs/trustScore"
    return url, {"type": "Property", "value": wrong}


# The victim is a confirmed message the run's own producer signed (never another writer's
# data), and never one an earlier trial already rewrote: flipping it again would restore it.
# A block that already carries an alert is skipped too, so an old alert cannot be mistaken
# for this trial's detection.
VICTIM_SQL = (
    "SELECT block_id, data FROM messages m WHERE tag = %s AND iss = %s AND data IS NOT NULL "
    "AND confirmed_at_ms IS NOT NULL AND NOT (block_id = ANY(%s)) "
    "AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.block_id = m.block_id) "
    "ORDER BY random() LIMIT 1"
)
TAMPER_SQL = (
    "UPDATE messages SET data = set_byte(data, 0, get_byte(data, 0) # 1) WHERE block_id = %s"
)
RESTORE_SQL = "UPDATE messages SET data = %s WHERE block_id = %s"
READ_DATA_SQL = "SELECT data FROM messages WHERE block_id = %s"


def log_original(path: Path, block_id: bytes, data: bytes) -> None:
    """Append the bytes a row held before A19 rewrote it, durably, before the rewrite."""
    entry = {"block": to_hex(block_id), "sha256": hashlib.sha256(data).hexdigest(),
             "original": data.hex()}
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
        f.flush()
        os.fsync(f.fileno())


def read_tamper_log(path: Path) -> dict[bytes, bytes]:
    """Block id -> original bytes, from a log written by `log_original` (first entry wins)."""
    out: dict[bytes, bytes] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        data = bytes.fromhex(entry["original"])
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"tamper log entry for {entry['block']} does not match its hash")
        out.setdefault(from_hex(entry["block"]), data)
    return out


async def restore_rows(conn: Any, originals: dict[bytes, bytes]) -> list[dict[str, Any]]:
    """Put each row's original bytes back and read them again. Returns one
    {block, ok} per row; ok is False when the row now holds anything else."""
    results = []
    for bid, data in originals.items():
        await conn.execute(RESTORE_SQL, (data, bid))
        cur = await conn.execute(READ_DATA_SQL, (bid,))
        row = await cur.fetchone()
        ok = row is not None and bytes(row[0]) == data
        results.append({"block": to_hex(bid), "ok": ok})
    return results


# ------------------------------------------------------------------ live helpers


async def _client(ctx: AttackContext) -> tuple[httpx.AsyncClient, bool]:
    if ctx.http is not None:
        return ctx.http, False
    return httpx.AsyncClient(timeout=10.0), True


async def _post_hornet(ctx: AttackContext, tag: str, data: bytes) -> str:
    ctx.require_live()
    path, body = hornet_request(tag, data)
    client, own = await _client(ctx)
    try:
        resp = await client.post(ctx.hornet_url.rstrip("/") + path, json=body)
        resp.raise_for_status()
        return resp.json()["blockId"]
    finally:
        if own:
            await client.aclose()


async def _post_relay(ctx: AttackContext, tag: str, message: Any) -> dict:
    ctx.require_live()
    url, body, headers = relay_upload(ctx, tag, message)
    client, own = await _client(ctx)
    try:
        resp = await client.post(url, json=body, headers=headers)
        resp.raise_for_status()
        return resp.json()
    finally:
        if own:
            await client.aclose()


SUBMISSIONS_TOPIC = "aerios/iota/submissions/"
INGEST_ROUTES = ("http", "mqtt", "both")


def submission_topic(tag: str) -> str:
    """The relay's MQTT topic for a submission record of `tag` (wildcards replaced)."""
    return SUBMISSIONS_TOPIC + tag.replace("+", "_").replace("#", "_").replace("\x00", "_")


def record_payload(record: dict) -> bytes:
    """A submission record as the relay publishes it: compact UTF-8 JSON."""
    return json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


async def mqtt_publish_once(url: str, topic: str, payload: bytes) -> None:
    """Publish one QoS 1 message (connect, publish, disconnect)."""
    import aiomqtt

    parts = urlsplit(url)
    if parts.scheme not in ("mqtt", "tcp"):
        raise ValueError(f"unsupported MQTT URL scheme: {parts.scheme!r}")
    async with aiomqtt.Client(
        hostname=parts.hostname or "127.0.0.1", port=parts.port or 1883,
        username=unquote(parts.username) if parts.username else None,
        password=unquote(parts.password) if parts.password else None,
        identifier=f"witness-chaos-{uuid.uuid4().hex[:8]}",
    ) as client:
        await client.publish(topic, payload=payload, qos=1)


async def _post_ingest(ctx: AttackContext, record: dict) -> list[str]:
    """Deliver a forged submission record the way the relay forwards real ones; returns
    the routes used. With "both" the explorer receives it twice and dedupes by subId."""
    ctx.require_live()
    if ctx.ingest_via not in INGEST_ROUTES:
        raise ValueError(f"ingest_via must be one of {INGEST_ROUTES}")
    used: list[str] = []
    failures: list[Exception] = []

    async def mqtt() -> None:
        payload = record_payload(record)
        topic = submission_topic(record["tag"])
        if ctx.mqtt_publish is not None:
            await ctx.mqtt_publish(topic, payload)
        else:
            await mqtt_publish_once(ctx.need("mqtt_url"), topic, payload)

    async def http() -> None:
        headers = {"Authorization": f"Bearer {ctx.ingest_token}"} if ctx.ingest_token else {}
        client, own = await _client(ctx)
        try:
            resp = await client.post(ctx.ingest_url, json=record, headers=headers)
            resp.raise_for_status()
        finally:
            if own:
                await client.aclose()

    for name, send in (("mqtt", mqtt), ("http", http)):
        if ctx.ingest_via not in (name, "both"):
            continue
        try:
            await send()
        except Exception as exc:  # noqa: BLE001 - one route failing must not hide the other
            failures.append(exc)
            used.append(f"{name}-failed: {type(exc).__name__}: {exc}"[:200])
        else:
            used.append(name)
    if len(failures) == len(used):
        raise failures[0]
    return used


async def _after(ctx: AttackContext, block_id: str | None) -> None:
    if ctx.wait_indexed is not None and block_id:
        await ctx.wait_indexed(block_id)


async def _direct(ctx: AttackContext, cid: str, tag: str, data: bytes,
                  ie_id: str | None = None, detail: dict | None = None) -> InjectionRecord:
    ctx.require_live()
    at = ctx.clock_ms()
    bid = await _post_hornet(ctx, tag, data)
    return _record(ctx, cid, bid, ie_id or ctx.ie_id, {"tag": tag, **(detail or {})}, at)


# ------------------------------------------------------------------ live attacks


async def a01_forged_signature(ctx: AttackContext) -> InjectionRecord:
    tag, data = build_a01(ctx)
    return await _direct(ctx, "A01", tag, data)


async def a02_cross_tag_replay(ctx: AttackContext) -> InjectionRecord:
    tag, data = build_a02(ctx)
    return await _direct(ctx, "A02", tag, data, detail={"envelopeTag": TRUST_TAG})


async def a03_seq_replay(ctx: AttackContext) -> InjectionRecord:
    ctx.require_live()
    (t1, d1), (t2, d2) = build_a03(ctx)
    first = await _post_hornet(ctx, t1, d1)
    await _after(ctx, first)
    rec = await _direct(ctx, "A03", t2, d2, detail={"originalBlockId": first})
    return rec


async def a04_unauthorized_writer(ctx: AttackContext) -> InjectionRecord:
    tag, data = build_a04(ctx)
    return await _direct(ctx, "A04", tag, data)


async def a05_revoked_key(ctx: AttackContext) -> InjectionRecord:
    tag, data = build_a05(ctx)
    return await _direct(ctx, "A05", tag, data)


async def a06_orion_drift(ctx: AttackContext) -> InjectionRecord:
    ctx.require_live()
    ctx.begin_trial()
    # The ledger score Orion will disagree with. It is genuine and goes the genuine way,
    # through the Messages API: posted around it, it would itself raise SHADOW, and the
    # attack here is the Orion write alone.
    seed = seal_as(ctx.need("producer"), ctx, score_body(ctx.ie_id, ctx.baseline_score))
    reply = await _post_relay(ctx, TRUST_TAG, seed)
    seed_bid = (reply.get("witness") or {}).get("blockId")
    url, body = orion_patch(ctx, ctx.ie_id, ctx.baseline_score)
    at = ctx.clock_ms()
    client, own = await _client(ctx)
    try:
        resp = await client.patch(url, json=body)
        resp.raise_for_status()
    finally:
        if own:
            await client.aclose()
    return _record(ctx, "A06", None, ctx.ie_id,
                   {"orionValue": body["value"], "ledgerScore": ctx.baseline_score,
                    "seedBlockId": seed_bid}, at)


def build_a11(ctx: AttackContext) -> dict:
    """Plaintext report for the sealed tag; `secret` is the marker that must never show."""
    return {"reportId": str(uuid.uuid4()), "secret": f"s{ctx.rng.getrandbits(64):016x}"}


def check_sealed(stored: Any, plaintext: dict) -> tuple[bool, str]:
    """A11 `sealed`: the stored envelope has `enc` and no `body`, none of the plaintext is
    visible in it, and decrypting without the recipient key fails."""
    if not isinstance(stored, dict) or not isinstance(stored.get("enc"), dict):
        return False, "stored message has no enc"
    if "body" in stored:
        return False, "stored message carries a plaintext body"
    text = json.dumps(stored)
    if any(str(v) in text for v in plaintext.values()):
        return False, "plaintext visible in the stored message"
    try:
        sealed.decrypt_body(stored["enc"], "did:none#kex-1", X25519PrivateKey.generate())
    except (sealed.NotARecipient, sealed.DecryptError):
        return True, "decrypt without the recipient key fails"
    return False, "decryption without the recipient key succeeded"


def blind_token_for(ctx: AttackContext, tag: str = SEALED_TAG) -> str:
    return sealed.blind_token(ctx.need("search_key"), "tag", tag)


def check_blind_search(result_block_ids: list[str], block_id: str | None) -> bool:
    """A11 `blind_search`: the lookup by blind token returns the injected block."""
    return block_id is not None and block_id.lower() in {b.lower() for b in result_block_ids}


async def a11_sealed_without_key(ctx: AttackContext) -> InjectionRecord:
    ctx.require_live()
    at = ctx.clock_ms()
    message = build_a11(ctx)
    reply = await _post_relay(ctx, SEALED_TAG, message)
    bid = (reply.get("witness") or {}).get("blockId")
    return _record(ctx, "A11", bid, None,
                   {"tag": SEALED_TAG, "plaintext": message,
                    "blindToken": blind_token_for(ctx),
                    "checks": ["sealed", "blind_search"]}, at)


async def a12_unknown_ie(ctx: AttackContext) -> InjectionRecord:
    tag, data, ie = build_a12(ctx)
    return await _direct(ctx, "A12", tag, data, ie_id=ie)


async def a13_score_jump(ctx: AttackContext) -> InjectionRecord:
    ctx.require_live()
    ctx.begin_trial()
    first, second = build_a13(ctx)
    first_bid = await _post_hornet(ctx, *first)
    await _after(ctx, first_bid)
    return await _direct(ctx, "A13", *second,
                         detail={"from": 0.9, "to": 0.1, "firstBlockId": first_bid})


async def a14_stale_ie(ctx: AttackContext) -> InjectionRecord:
    ctx.require_live()
    ctx.begin_trial()
    tag, data = build_a14(ctx)
    return await _direct(ctx, "A14", tag, data, ie_id=ctx.stale_ie_id)


async def a15_malformed_payload(ctx: AttackContext) -> InjectionRecord:
    tag, data = build_a15(ctx)
    return await _direct(ctx, "A15", tag, data)


async def a16_content_mismatch(ctx: AttackContext) -> InjectionRecord:
    ctx.require_live()
    ctx.begin_trial()
    tag, data = build_a17(ctx)
    at = ctx.clock_ms()
    bid = await _post_hornet(ctx, tag, data)
    routes = await _post_ingest(ctx, build_a16_record(bid, tag, data, at))
    return _record(ctx, "A16", bid, ctx.ie_id, {"tag": tag, "ingest": routes}, at)


async def a17_shadow(ctx: AttackContext) -> InjectionRecord:
    ctx.require_live()
    ctx.begin_trial()
    tag, data = build_a17(ctx)
    return await _direct(ctx, "A17", tag, data)


async def a18_orphaned(ctx: AttackContext) -> InjectionRecord:
    ctx.require_live()
    ctx.begin_trial()
    record = build_a18_record(ctx)
    at = ctx.clock_ms()
    routes = await _post_ingest(ctx, record)
    return _record(ctx, "A18", record["blockId"], ctx.ie_id,
                   {"subId": record["subId"], "ingest": routes}, at)


async def a19_db_tamper(ctx: AttackContext) -> InjectionRecord:
    ctx.require_live()
    import psycopg

    dsn = ctx.need("db_dsn")
    iss = ctx.need("producer").iss
    async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as conn:
        cur = await conn.execute(VICTIM_SQL, (TRUST_TAG, iss, list(ctx.tampered)))
        row = await cur.fetchone()
        if row is None:
            raise RuntimeError(f"no confirmed trust.score row signed by {iss} to tamper with")
        bid, original = bytes(row[0]), bytes(row[1])
        if ctx.tamper_log is not None:
            log_original(ctx.tamper_log, bid, original)
        ctx.originals.setdefault(bid, original)
        ctx.tampered.append(bid)
        at = ctx.clock_ms()
        await conn.execute(TAMPER_SQL, (bid,))
    return _record(ctx, "A19", to_hex(bytes(row[0])), None,
                   {"sql": TAMPER_SQL, "victimIss": iss}, at)


async def a20_chain_gap(ctx: AttackContext) -> InjectionRecord:
    ctx.require_live()
    ctx.begin_trial()
    m1, m3, missing = build_a20(ctx)
    first = await _post_relay(ctx, TRUST_TAG, m1)
    await _after(ctx, (first.get("witness") or {}).get("blockId"))
    at = ctx.clock_ms()
    reply = await _post_relay(ctx, TRUST_TAG, m3)
    bid = (reply.get("witness") or {}).get("blockId")
    return _record(ctx, "A20", bid, ctx.ie_id, {"missingPrev": missing}, at)


# ------------------------------------------------------------------ positive control


def build_c01(ctx: AttackContext) -> dict:
    """A genuine producer-signed score, exactly what the Trust Manager uploads."""
    return seal_as(ctx.need("producer"), ctx, score_body(ctx.ie_id, ctx.baseline_score))


async def c01_relay_routed(ctx: AttackContext) -> InjectionRecord:
    """C01: the A17 block's twin sent the right way, through the Messages API. Nothing may
    alert on it (no SHADOW in particular) within the A17 timeout."""
    ctx.require_live()
    ctx.begin_trial()
    env = build_c01(ctx)
    at = ctx.clock_ms()
    reply = await _post_relay(ctx, TRUST_TAG, env)
    bid = (reply.get("witness") or {}).get("blockId")
    return _record(ctx, "C01", bid, ctx.ie_id,
                   {"tag": TRUST_TAG, "relayVerdict": (reply.get("witness") or {}).get("verdict")},
                   at)


CONTROLS: dict[str, Callable[[AttackContext], Awaitable[InjectionRecord]]] = {
    "C01": c01_relay_routed,
}


# ------------------------------------------------------------------ offline attacks


def _ladder_detail(ctx: AttackContext, b: dict) -> dict:
    cfg = ctx.need("verifier")
    fetch = ctx.anchor_fetch or forge_fetch(ctx)
    ladder = bundle.verify(b, cfg, fetch)
    return {
        "overall": ladder.overall,
        "steps": {s.name: s.ok for s in ladder.steps},
        "details": {s.name: s.detail for s in ladder.steps},
    }


def forge_fetch(ctx: AttackContext) -> Callable[[dict], dict | None]:
    """Fetcher serving the genuine record of the run's real bundle."""
    record = forge.real_anchor_record(ctx.need("real_bundle"))
    return lambda _anchor: record


def parses(b: dict) -> bool:
    try:
        codec.parse_block(bytes.fromhex(b["block"]["raw"][2:]))
    except (codec.DecodeError, ValueError, KeyError):
        return False
    return True


def meets_offline_expectation(expect: dict, detail: dict) -> bool:
    """Does the ladder outcome recorded in `detail` match an offline `expect`?"""
    want = expect["ladder"]
    if detail["steps"].get(want["step"]) is not want["ok"]:
        return False
    return "parses" not in want or detail.get("parses") is want["parses"]


def _offline(ctx: AttackContext, cid: str, b: dict) -> InjectionRecord:
    at = ctx.clock_ms()
    detail = _ladder_detail(ctx, b)
    detail["parses"] = parses(b)
    detail["bundle"] = b
    return _record(ctx, cid, b["block"]["id"], None, detail, at)


async def a07_block_byte_flip(ctx: AttackContext) -> InjectionRecord:
    b = forge.tamper_bundle(ctx.need("real_bundle"), "byte_flip", ctx.rng)
    return _offline(ctx, "A07", b)


async def a08_bad_merkle_path(ctx: AttackContext) -> InjectionRecord:
    b = forge.tamper_bundle(ctx.need("real_bundle"), "merkle_path", ctx.rng)
    return _offline(ctx, "A08", b)


async def a09_sample_key_forged_milestone(ctx: AttackContext) -> InjectionRecord:
    b = forge.forge_milestone_bundle(ctx.need("real_bundle"), ctx.sample_private_keys)
    return _offline(ctx, "A09", b)


async def a10_anchor_mismatch(ctx: AttackContext) -> InjectionRecord:
    b = forge.tamper_bundle(ctx.need("real_bundle"), "checkpoint", ctx.rng)
    return _offline(ctx, "A10", b)
