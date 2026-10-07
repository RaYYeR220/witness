"""The modified aeriOS IOTA Messages API.

Same contract as eclipse-aerios/iota-messages-api (`POST /upload?node=<name>` with
`{tag, message}`, success = HTTP 200 + `{"return_payload", "status_code"}` rendered the
way Flask's `jsonify` does), plus:

- `node` must be one of the configured nodes (the original builds a URL from it);
- messages are signed: producer envelopes are verified and passed through, anything
  else is wrapped in a relay-attested envelope; the writer policy is enforced;
- a producer's `seq` is claimed atomically before sending, so replays are refused;
- legacy messages on configured tags are encrypted to the recipients before they are
  attested (producer envelopes are the producer's own business, sealed or not);
- tags listed in `RELAY_PASSTHROUGH_TAGS` keep the original behaviour for legacy
  messages: the data is `json.dumps(message)` exactly as the original API sends it, with
  no envelope (verdict `UNSIGNED_LEGACY`), still receipted and forwarded;
- receipts and per-issuer sequence numbers are kept in PostgreSQL;
- every submission attempt, failed ones included, is forwarded to the explorer.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from typing import Any

import httpx
import psycopg
from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from witness_core import envelope, nesting, verdicts

from .attest import Attestor, block_size, envelope_data, legacy_data, load_signing_key
from .auth import AuthError, AuthUnavailable, CallerAuth
from .config import RelayConfig, load_search_key
from .forward import Forwarder, ForwardQueue, build_forwarders
from .keys import KeyResolver, KeysUnavailable
from .policy_gate import Decision, PolicyGate, load_policy, tags_without_relay
from .receipts import Receipt, ReceiptStore

log = logging.getLogger("witness_relay")

HORNET_NOT_FOUND = "Hornet node not found, check that the Hornet node exists.\n"
# Upload bodies larger than this many blocks cannot fit and are not even buffered.
MAX_REQUEST_FACTOR = 8
TAG_MAX_BYTES = 64  # Stardust tagged-data limit


def _now_ms() -> int:
    return int(time.time() * 1000)


def legacy_json(obj: Any, status: int) -> Response:
    """Render like Flask's jsonify in debug mode: sorted keys, indent 2, trailing newline."""
    text = json.dumps(obj, indent=2, sort_keys=True) + "\n"
    return Response(text, status_code=status, media_type="application/json")


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):  # e.g. 1e400
        raise ValueError(f"{text} is not a finite number")
    return value


@dataclass
class Submission:
    """What happened to one upload; becomes the forwarded record."""

    sub_id: str
    received_at_ms: int
    tag: str
    message: Any
    verdict: str | None = None
    iss: str | None = None
    seq: int | None = None
    data: bytes | None = None
    block_id: str | None = None
    hornet_status: int | None = None
    # A legacy message on an encrypted tag: its plaintext leaves the relay only sealed, so
    # the forwarded record carries no `message` (whether or not the upload succeeded).
    sealed: bool = False

    def apply(self, d: Decision) -> None:
        self.verdict, self.iss, self.seq = d.verdict, d.iss, d.seq

    def record(self) -> dict:
        return {
            "subId": self.sub_id,
            "receivedAtMs": self.received_at_ms,
            "tag": self.tag,
            "message": None if self.sealed else self.message,
            "messageSealed": self.sealed,
            "dataHex": "0x" + self.data.hex() if self.data is not None else None,
            "blockId": self.block_id,
            "hornetStatus": self.hornet_status,
            "relay": {"verdict": self.verdict, "iss": self.iss, "seq": self.seq},
        }

    def witness(self) -> dict:
        return {
            "blockId": self.block_id,
            "verdict": self.verdict,
            "iss": self.iss,
            "seq": self.seq,
            "subId": self.sub_id,
        }


class HornetUnreachable(Exception):
    def __init__(self, sent: bool):
        self.sent = sent


@dataclass
class Relay:
    cfg: RelayConfig
    attestor: Attestor
    gate: PolicyGate
    auth: CallerAuth
    store: ReceiptStore
    forward: ForwardQueue
    http: httpx.AsyncClient
    chain_lock: asyncio.Lock

    async def submit(self, base_url: str, tag: str, data: bytes) -> httpx.Response:
        payload = json.dumps(
            {
                "protocolVersion": 2,
                "payload": {
                    "type": 5,
                    "tag": "0x" + tag.encode("utf-8").hex(),
                    "data": "0x" + data.hex(),
                },
            }
        )
        try:
            return await self.http.post(
                base_url.rstrip("/") + "/api/core/v2/blocks",
                content=payload,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
        except httpx.ConnectError as exc:
            log.warning("HORNET at %s unreachable: %s", base_url, exc)
            raise HornetUnreachable(sent=False) from exc
        except httpx.HTTPError as exc:
            log.warning("HORNET at %s failed mid-request: %r", base_url, exc)
            raise HornetUnreachable(sent=True) from exc


async def _read_capped(request: Request, limit: int) -> bytes | None:
    """The request body, or None as soon as it is known to exceed `limit`."""
    try:
        if int(request.headers.get("content-length") or 0) > limit:
            return None
    except ValueError:
        return None
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            return None
    return bytes(body)


def _block_id(resp: httpx.Response) -> str | None:
    try:
        bid = resp.json().get("blockId")
    except (ValueError, AttributeError):
        return None
    return bid if isinstance(bid, str) else None


async def _handle(
    relay: Relay, request: Request, node: str, base_url: str, sub: Submission
) -> Response:
    tag, message = sub.tag, sub.message

    def refuse(d: Decision) -> Response:
        log.info("refused upload to %r: %s (%s)", tag, d.verdict, d.reason)
        return JSONResponse({"error": d.reason, "verdict": d.verdict}, status_code=d.status)

    if envelope.is_envelope(message):
        try:
            decision = await relay.gate.check_envelope(tag, message)
        except KeysUnavailable as exc:
            # Not a verdict: the signer's key could not be looked up. Retry later.
            log.warning("cannot check an envelope for %r now: %s", tag, exc)
            return JSONResponse(
                {"error": f"signing key cannot be resolved right now, retry later: {exc}"},
                status_code=503,
                headers={"retry-after": "5"},
            )
        sub.apply(decision)
        if not decision.allowed:
            return refuse(decision)
        data = envelope_data(message)
        if block_size(tag, data) > relay.cfg.max_block_bytes:
            return _too_large(relay.cfg)
        try:
            previous = await relay.store.reserve(decision.iss, decision.seq)
        except Exception:
            log.exception("cannot reserve seq %s for %s", decision.seq, decision.iss)
            return JSONResponse({"error": "receipt store unavailable"}, status_code=503)
        if previous is None:
            sub.verdict = verdicts.REPLAY
            return refuse(
                replace(
                    decision,
                    allowed=False,
                    verdict=verdicts.REPLAY,
                    reason=f"seq {decision.seq} is not newer than the last from {decision.iss}",
                )
            )
        claim = (decision.iss, decision.seq, previous)
        nonce = message.get("nonce")
        return await _send(relay, node, base_url, sub, decision, data, claim=claim,
                           nonce=nonce if isinstance(nonce, str) else None)

    try:
        caller = await relay.auth.caller(request.headers.get("authorization"))
    except AuthUnavailable as exc:
        log.error("caller authentication unavailable: %s", exc)
        return JSONResponse({"error": "caller authentication unavailable"}, status_code=503)
    except AuthError as exc:
        sub.verdict = verdicts.UNAUTHORIZED_WRITER
        return JSONResponse({"error": str(exc), "verdict": sub.verdict}, status_code=403)
    decision = relay.gate.check_legacy(tag, caller)
    sub.verdict = decision.verdict
    if not decision.allowed:
        return refuse(decision)

    if decision.mode == "passthrough":
        if nesting.containers_too_deep(message):
            return _too_deep(sub)
        data = legacy_data(message)
        if block_size(tag, data) > relay.cfg.max_block_bytes:
            return _too_large(relay.cfg)
        return await _send(relay, node, base_url, sub, decision, data)

    try:
        content = relay.attestor.protect(tag, message)
        too_big = (
            relay.attestor.worst_case_size(tag, content, caller=caller) > relay.cfg.max_block_bytes
        )
    except (ValueError, RecursionError) as exc:  # not canonicalizable: big ints, too deep
        return JSONResponse({"error": f"message cannot be signed: {exc}"}, status_code=400)
    if too_big:
        sub.iss = decision.iss
        return _too_large(relay.cfg)
    if "body" in content and nesting.containers_too_deep({"body": content["body"]}):
        return _too_deep(sub)  # as the envelope the relay would post

    async with relay.chain_lock:
        try:
            seq, prev = await relay.store.allocate(relay.cfg.relay_did)
        except Exception:
            log.exception("cannot allocate a sequence number")
            return JSONResponse({"error": "receipt store unavailable"}, status_code=503)
        env = relay.attestor.seal(tag, content, caller=caller, seq=seq, prev=prev)
        sub.iss, sub.seq = env["iss"], seq
        # Still under the chain lock, so a release cannot race the next allocation.
        claim = (relay.cfg.relay_did, seq, seq - 1)
        return await _send(
            relay, node, base_url, sub, decision, envelope_data(env), kid=env["kid"], claim=claim
        )


async def _release(relay: Relay, claim: tuple[str, int, int] | None) -> None:
    """Give back a claimed seq when the block definitely never reached the Tangle."""
    if claim is None:
        return
    iss, seq, previous = claim
    try:
        await relay.store.release(iss, seq, previous)
    except Exception:
        log.exception("could not release seq %s of %s", seq, iss)


async def _persist(relay: Relay, receipt: Receipt) -> None:
    """Store the receipt; if that fails, still move the issuer's chain head (once more)."""
    try:
        await relay.store.record(receipt)
        return
    except Exception:
        # The block is on the Tangle already; the client still gets its id.
        log.exception("could not persist receipt for %s", receipt.block_id)
    if receipt.iss is None or receipt.seq is None:
        return
    try:
        await relay.store.advance(receipt.iss, receipt.seq, receipt.block_id)
    except Exception:
        log.exception("could not advance the chain head of %s", receipt.iss)


async def _send(
    relay: Relay,
    node: str,
    base_url: str,
    sub: Submission,
    decision: Decision,
    data: bytes,
    *,
    kid: str | None = None,
    claim: tuple[str, int, int] | None = None,
    nonce: str | None = None,
) -> Response:
    try:
        resp = await relay.submit(base_url, sub.tag, data)
    except HornetUnreachable as exc:
        sub.data = data if exc.sent else None
        if not exc.sent:
            await _release(relay, claim)
        return PlainTextResponse(HORNET_NOT_FOUND, status_code=400, media_type="text/html")
    sub.data = data
    sub.hornet_status = resp.status_code
    if resp.status_code >= 400:
        log.warning(
            "HORNET refused block for %r: %s %s", sub.tag, resp.status_code, resp.text[:200]
        )
        if resp.status_code < 500:  # rejected outright: nothing was stored
            await _release(relay, claim)
        return legacy_json(
            {
                "status_code": resp.status_code,
                "return_payload": resp.text,
                "witness": sub.witness(),
            },
            502,
        )
    sub.block_id = _block_id(resp)
    if sub.block_id is not None:
        await _persist(
            relay,
            Receipt(
                block_id=sub.block_id,
                sub_id=sub.sub_id,
                tag=sub.tag,
                iss=sub.iss,
                kid=kid or decision.kid,
                seq=sub.seq,
                verdict=sub.verdict,
                att_sub=decision.caller,
                node=node,
                hornet_status=resp.status_code,
                received_at_ms=sub.received_at_ms,
                nonce=nonce,
            ),
        )
    return legacy_json(
        {"status_code": resp.status_code, "return_payload": resp.text, "witness": sub.witness()},
        200,
    )


def _too_deep(sub: Submission) -> Response:
    """The explorer reads no message nested past nesting.MAX_MESSAGE_DEPTH (it records it
    MALFORMED), so the relay does not post one."""
    sub.verdict = verdicts.MALFORMED
    return JSONResponse({"error": "message nested too deeply", "verdict": sub.verdict},
                        status_code=400)


def _too_large(cfg: RelayConfig) -> Response:
    return JSONResponse(
        {"error": f"message exceeds the {cfg.max_block_bytes}-byte block limit"},
        status_code=413,
    )


def create_app(cfg: RelayConfig, *, forwarders: list[Forwarder] | None = None) -> FastAPI:
    attestor = Attestor(
        did=cfg.relay_did,
        kid=cfg.relay_kid,
        key=load_signing_key(cfg.relay_key_path),
        encrypt_tags=frozenset(cfg.encrypt_tags),
        recipients=tuple(cfg.recipients),
        search_key=load_search_key(cfg.search_key_path) if cfg.search_key_path else None,
    )
    overlap = set(cfg.encrypt_tags) & set(cfg.passthrough_tags)
    if overlap:
        raise ValueError(f"tags cannot be both encrypted and passed through: {sorted(overlap)}")
    writer_policy = load_policy(cfg.policy_path)
    for tag in tags_without_relay(writer_policy, cfg.relay_did):
        if tag not in cfg.passthrough_tags:
            log.warning(
                "writer policy for %s does not allow the relay DID; relay-attested messages "
                "there will be flagged UNAUTHORIZED_WRITER by the explorer",
                tag,
            )
    sinks = build_forwarders(cfg) if forwarders is None else list(forwarders)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        http = httpx.AsyncClient(timeout=cfg.hornet_timeout_s)
        store = await ReceiptStore.open(cfg.db_url, cfg.db_schema)
        queue = ForwardQueue(sinks, maxsize=cfg.forward_queue_size)
        resolver = KeyResolver.from_files(
            cfg.trusted_keys_path, resolver_url=cfg.resolver_url, http=http
        )
        app.state.relay = Relay(
            cfg=cfg,
            attestor=attestor,
            gate=PolicyGate(
                writer_policy,
                resolver,
                cfg.relay_did,
                passthrough_tags=cfg.passthrough_tags,
                replay_check=store.replay_reason,
            ),
            auth=CallerAuth(
                cfg.keycloak_jwks_url, http, audience=cfg.jwt_audience, issuer=cfg.jwt_issuer
            ),
            store=store,
            forward=queue,
            http=http,
            chain_lock=asyncio.Lock(),
        )
        await queue.start()
        if not sinks:
            log.warning("no forwarding sinks configured; submissions reach no explorer")
        log.info(
            "relay %s ready; nodes=%s sinks=%s",
            cfg.relay_did,
            sorted(cfg.allowed_nodes),
            [s.name for s in sinks],
        )
        try:
            yield
        finally:
            await queue.stop(cfg.forward_drain_s)
            await http.aclose()
            await store.close()

    app = FastAPI(title="witness-relay", version="0.1.0", lifespan=lifespan)

    @app.post("/upload")
    async def upload(request: Request, node: str | None = None) -> Response:
        relay: Relay = request.app.state.relay
        received_at = _now_ms()
        base_url = relay.cfg.allowed_nodes.get(node) if node else None
        if base_url is None:
            return JSONResponse({"error": "unknown node"}, status_code=400)
        raw = await _read_capped(request, MAX_REQUEST_FACTOR * relay.cfg.max_block_bytes)
        if raw is None:
            return _too_large(relay.cfg)
        try:
            req = nesting.loads(raw, parse_constant=_reject_constant, parse_float=_finite_float)
            # Lone surrogates parse but can be neither signed, sent nor forwarded.
            json.dumps(req, ensure_ascii=False).encode("utf-8")
        except nesting.JsonTooDeep as exc:
            return JSONResponse({"error": f"body is {exc}"}, status_code=400)
        except ValueError:  # includes UnicodeEncodeError
            return JSONResponse(
                {"error": "body must be JSON with finite numbers and valid Unicode"},
                status_code=400,
            )
        if not (isinstance(req, dict) and isinstance(req.get("tag"), str) and "message" in req):
            return JSONResponse(
                {"error": 'body must be {"tag": str, "message": any}'}, status_code=400
            )
        tag, message = req["tag"], req["message"]
        if len(tag.encode("utf-8")) > TAG_MAX_BYTES:
            return JSONResponse({"error": f"tag exceeds {TAG_MAX_BYTES} bytes"}, status_code=400)

        sealed = tag in relay.cfg.encrypt_tags and not envelope.is_envelope(message)
        sub = Submission(str(uuid.uuid4()), received_at, tag, message, sealed=sealed)
        try:
            return await _handle(relay, request, node, base_url, sub)
        finally:
            relay.forward.submit(sub.record())

    @app.get("/receipts")
    async def receipts(
        request: Request,
        tag: str | None = None,
        iss: str | None = None,
        limit: int = Query(50, ge=1, le=1000),
    ) -> dict:
        rows = await request.app.state.relay.store.receipts(tag=tag, iss=iss, limit=limit)
        return {
            "receipts": [
                {
                    "blockId": r["block_id"],
                    "subId": r["sub_id"],
                    "tag": r["tag"],
                    "iss": r["iss"],
                    "kid": r["kid"],
                    "seq": r["seq"],
                    "verdict": r["verdict"],
                    "attSub": r["att_sub"],
                    "node": r["node"],
                    "hornetStatus": r["hornet_status"],
                    "receivedAtMs": r["received_at_ms"],
                }
                for r in rows
            ]
        }

    @app.get("/healthz")
    async def healthz(request: Request) -> JSONResponse:
        relay: Relay = request.app.state.relay
        try:
            db_ok = await asyncio.wait_for(relay.store.ping(), 2.0)
        except (psycopg.Error, OSError, TimeoutError):
            db_ok = False
        body = {
            "status": "ok" if db_ok else "degraded",
            "relay": relay.cfg.relay_did,
            "db": db_ok,
            "forward": relay.forward.stats(),
        }
        return JSONResponse(body, status_code=200 if db_ok else 503)

    return app
