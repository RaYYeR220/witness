"""Signed audit reports: build the report over the stored data, hash it canonically, render
an offline HTML page, and post the hash back to the Tangle as an `audit.report` message.

The report hash is `canon_hash` (BLAKE2b-256 of the RFC 8785 form) of the report JSON, so
anyone can recompute it from the JSON and check it against the on-chain `audit.report`
message. The HTML shows that hash, says plainly whether it has been anchored, and is
self-contained (no external assets)."""

from __future__ import annotations

import base64
import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jinja2 import Environment, FileSystemLoader, select_autoescape
from witness_core import canon, envelope

log = logging.getLogger(__name__)

VERSION = 1
KIND = "witness.audit-report"
TAG = "audit.report"
# The template ships at api/templates/ (source tree) and, in a built wheel, next to this
# module; search both so rendering works either way.
_HERE = Path(__file__).resolve()
TEMPLATE_DIRS = [str(_HERE.parents[2] / "templates"), str(_HERE.parent / "templates")]
PROOF_INDEX_LIMIT = 200

_env = Environment(loader=FileSystemLoader(TEMPLATE_DIRS),
                   autoescape=select_autoescape(["html"]))


def now_ms() -> int:
    return int(time.time() * 1000)


async def build(store, *, network: str, ie: str | None = None, frm: int | None = None,
                to: int | None = None, at_ms: int | None = None,
                proof_limit: int = PROOF_INDEX_LIMIT) -> dict:
    """The report JSON: message totals by verdict, alert and anchor summaries, and an index
    of the confirmed messages in range (each has a proof bundle). Every total is counted in
    SQL over the whole range; only the proof index is capped (`proofsTruncated`).
    Deterministic given the store contents and `at_ms`."""
    generated = now_ms() if at_ms is None else at_ms
    by_verdict: dict[str, int] = {}
    total = encrypted = 0
    for r in await store.report_verdicts(ie=ie, ms_from=frm, ms_to=to):
        n = int(r["n"])
        total += n
        verdict = r["verdict"] or "UNKNOWN"
        by_verdict[verdict] = by_verdict.get(verdict, 0) + n
        if r["encrypted"]:
            encrypted += n
    by_severity: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for r in await store.report_alerts(ie=ie, ms_from=frm, ms_to=to):
        n = int(r["n"])
        by_severity[r["severity"]] = by_severity.get(r["severity"], 0) + n
        by_rule[r["rule"]] = by_rule.get(r["rule"], 0) + n
    anchor_counts, latest = await store.report_anchors(ms_from=frm, ms_to=to)
    by_status = {r["status"]: int(r["n"]) for r in anchor_counts}
    confirmed = await store.report_confirmed(ie=ie, ms_from=frm, ms_to=to)
    msgs = await store.report_messages(ie=ie, ms_from=frm, ms_to=to, limit=proof_limit)
    return {
        "v": VERSION,
        "kind": KIND,
        "network": network,
        "generatedAt": generated,
        "range": {"msFrom": frm, "msTo": to},
        "ie": ie,
        "messages": {
            "total": total,
            "encrypted": encrypted,
            "plaintext": total - encrypted,
            "confirmed": confirmed,
            "byVerdict": dict(sorted(by_verdict.items())),
        },
        "alerts": {
            "total": sum(by_severity.values()),
            "bySeverity": dict(sorted(by_severity.items())),
            "byRule": dict(sorted(by_rule.items())),
        },
        "anchors": {
            "total": sum(by_status.values()),
            "byStatus": dict(sorted(by_status.items())),
            "latest": _anchor_brief(latest) if latest else None,
        },
        "proofs": [_proof_entry(m) for m in msgs],
        "proofsTruncated": confirmed > len(msgs),
    }


def _anchor_brief(row: dict) -> dict:
    return {"seq": row["seq"], "fromMilestone": row["from_ms"], "toMilestone": row["to_ms"],
            "status": row["status"], "network": row["network"],
            "record": row["record"], "tx": row["tx"]}


def _proof_entry(row: dict) -> dict:
    block_id = "0x" + bytes(row["block_id"]).hex()
    return {"blockId": block_id, "tag": row["tag"], "kind": row["kind"], "ieId": row["ie_id"],
            "iss": row["iss"], "verdict": row["verdict"], "msIndex": row["ms_index"],
            "wfIndex": row["wf_index"], "proof": f"/proofs/{block_id}"}


def report_hash(report: dict) -> bytes:
    """BLAKE2b-256 of the report's canonical JSON — its stable identifier."""
    return canon.canon_hash(report)


def render_html(report: dict, report_hash_hex: str, *, anchored: bool = False,
                block_id: str | None = None, signer: str | None = None) -> str:
    """Render the self-contained HTML page. Autoescape is on; no external assets. A report
    that is not anchored says so in plain words."""
    return _env.get_template("report.html").render(
        report=report, report_hash=report_hash_hex, anchored=anchored, block_id=block_id,
        signer=signer)


def report_body(report_hash_hex: str, report: dict) -> dict:
    """The `audit.report` message body posted to the Tangle (schema: reportHash,
    generatedAt, range?, ie?). It names the report by hash; the report stays off-chain."""
    body: dict[str, Any] = {"reportHash": report_hash_hex, "generatedAt": report["generatedAt"]}
    rng = report.get("range") or {}
    if rng.get("msFrom") is not None or rng.get("msTo") is not None:
        body["range"] = {k: v for k, v in rng.items() if v is not None}
    if report.get("ie"):
        body["ie"] = report["ie"]
    return body


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_signer(path: str) -> tuple[str, str, Ed25519PrivateKey]:
    """Load an Ed25519 signing key from an OKP private JWK; return (iss DID, kid, key).

    The key material is never logged or returned in any API response."""
    jwk = json.loads(Path(path).read_bytes())
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "d" not in jwk:
        raise ValueError("report signer key is not an Ed25519 private JWK")
    kid = jwk.get("kid")
    if not isinstance(kid, str) or "#" not in kid:
        raise ValueError("report signer JWK has no `kid` with a verification-method fragment")
    key = Ed25519PrivateKey.from_private_bytes(_b64u_decode(jwk["d"]))
    return kid.partition("#")[0], kid, key


class RelayError(Exception):
    """The relay refused the report or could not be reached (no secret in the message)."""


class NotWitnessRelay(Exception):
    """The configured relay URL answers, but not as a witness-relay."""


async def check_relay(http: httpx.AsyncClient, relay_url: str, *,
                      timeout_s: float = 5.0) -> str:
    """Make sure `relay_url` is a witness-relay before anything is posted through it.

    witness-relay's `GET /healthz` names its DID (`relay`) and its forwarding queue
    (`forward`); the legacy aeriOS Messages API has no such endpoint and would post the
    envelope without enforcing the writer policy. Returns the relay's DID."""
    try:
        resp = await http.get(relay_url.rstrip("/") + "/healthz", timeout=timeout_s)
    except httpx.HTTPError as e:
        raise RelayError(f"relay unreachable ({type(e).__name__})") from None
    try:
        body = resp.json()
    except ValueError:
        body = None
    did = body.get("relay") if isinstance(body, dict) else None
    if not (isinstance(did, str) and did.startswith("did:")
            and isinstance(body.get("forward"), dict)):
        raise NotWitnessRelay()
    if resp.status_code != 200:
        raise RelayError(f"relay is degraded (status {resp.status_code})")
    return did


async def post_report(http: httpx.AsyncClient, *, relay_url: str, node: str,
                      signer: tuple[str, str, Ed25519PrivateKey], body: dict, seq: int,
                      timeout_s: float = 15.0) -> str:
    """Seal `body` as a producer envelope with sequence number `seq` and post it through
    the relay; return the block id."""
    iss, kid, key = signer
    env = envelope.seal(TAG, body, iss=iss, kid=kid, sign_key=key, seq=seq,
                        att_mode="producer")
    url = relay_url.rstrip("/") + "/upload"
    try:
        resp = await http.post(url, params={"node": node},
                               json={"tag": TAG, "message": env}, timeout=timeout_s)
    except httpx.HTTPError as e:
        raise RelayError(f"relay unreachable ({type(e).__name__})") from None
    try:
        reply = resp.json()
    except ValueError:
        reply = {}
    if resp.status_code != 200:
        verdict = reply.get("verdict") if isinstance(reply, dict) else None
        raise RelayError(f"relay rejected the report (status {resp.status_code}"
                         + (f", {verdict}" if verdict else "") + ")")
    block_id = (reply.get("witness") or {}).get("blockId") if isinstance(reply, dict) else None
    if not (isinstance(block_id, str) and len(block_id) == 66 and block_id.startswith("0x")):
        raise RelayError("relay accepted the report but returned no block id")
    try:
        bytes.fromhex(block_id[2:])
    except ValueError:
        raise RelayError("relay returned a malformed block id") from None
    return block_id.lower()
