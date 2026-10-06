"""Learning anchors from the `witness.anchor` mirror messages on the private Tangle.

The anchor service posts every checkpoint it wrote to IOTA Rebased as a `witness.anchor`
envelope signed with its own DID. Only a message that is PRODUCER_SIGNED by the pinned anchor
DID and has the full mirror shape becomes a row of `anchors` (seq = the checkpoint seq). R11
later checks each row against the on-chain record, never against this mirror.

A second mirror for a seq that is already stored is ignored when it carries the same
checkpoint, and raises a critical ANCHOR_MISMATCH when it does not: one seq, two histories.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from witness_core import verdicts
from witness_core.ids import from_hex, to_hex

from . import events
from .classify import Decoded
from .store import Alert, MessageRow, Store

log = logging.getLogger(__name__)

TAG = "witness.anchor"
SERVICE = "anchor-mirror"
# deploy/identity/<network>.json of the repository, when running from a checkout.
IDENTITY_DIR = Path(__file__).resolve().parents[3] / "deploy" / "identity"


def default_anchor_did(network: str, identity_dir: Path = IDENTITY_DIR) -> str | None:
    """The DID of the `anchor` component in deploy/identity/<network>.json, if there is one."""
    path = identity_dir / f"{network}.json"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    for entry in doc.get("identities", []) if isinstance(doc, dict) else []:
        if isinstance(entry, dict) and entry.get("name") == "anchor":
            did = entry.get("did")
            return did if isinstance(did, str) and did.startswith("did:") else None
    return None


class AnchorIngest:
    def __init__(self, anchor_did: str | None) -> None:
        self.anchor_did = anchor_did or None

    def status(self) -> tuple[str, str]:
        if self.anchor_did is None:
            return "off", "no anchor DID pinned (--anchor-did); witness.anchor mirrors ignored"
        return "on", f"anchors learned from {TAG} messages of {self.anchor_did}"

    async def publish_status(self, store: Store) -> None:
        status, detail = self.status()
        await store.set_service_status(SERVICE, status, detail=detail)

    def accepts(self, row: MessageRow, d: Decoded) -> bool:
        return (
            self.anchor_did is not None
            and row.tag == TAG
            and row.verdict == verdicts.PRODUCER_SIGNED
            and row.iss == self.anchor_did
            and d.classified.schema_ok
            and isinstance(d.classified.json, dict)
        )

    async def on_message(self, store: Store, row: MessageRow, d: Decoded, now_ms: int,
                         pending: list[tuple[str, dict]]) -> None:
        """Store the anchor a genuine mirror announces (inside the milestone transaction)."""
        if not self.accepts(row, d):
            return
        body = d.classified.json
        cp, rebased, seq = body["checkpoint"], body["rebased"], body["seq"]
        digest = from_hex(body["checkpointHash"])
        existing = await store.anchor(seq)
        if existing is None:
            stored = await store.put_anchor(
                seq=seq, from_ms=cp["from"]["index"], to_ms=cp["to"]["index"],
                ms_root=from_hex(cp["msRoot"]), checkpoint=cp, checkpoint_hash=digest,
                network=rebased["network"], tx=rebased["tx"], record=rebased["record"],
                status="anchored", created_at_ms=row.ts * 1000)
            if stored:
                pending.append((events.ANCHOR, {
                    "seq": seq, "from": cp["from"]["index"], "to": cp["to"]["index"],
                    "checkpointHash": body["checkpointHash"], "network": rebased["network"],
                    "trail": rebased["trail"], "record": rebased["record"], "tx": rebased["tx"],
                    "blockId": to_hex(row.block_id),
                }))
            return
        known = existing.get("checkpoint_hash")
        if known is None or bytes(known) == digest:
            return  # the same checkpoint mirrored again
        log.error("anchor seq %d mirrored with checkpoint %s, already stored as %s", seq,
                  body["checkpointHash"], to_hex(bytes(known)))
        evidence = {
            "seq": seq, "blockId": to_hex(row.block_id), "iss": row.iss,
            "storedCheckpointHash": to_hex(bytes(known)),
            "mirrorCheckpointHash": body["checkpointHash"],
            "window": {"from": cp["from"]["index"], "to": cp["to"]["index"]},
            "rebased": rebased,
            "reason": "the anchor DID mirrored two different checkpoints under one seq",
        }
        alert = Alert("ANCHOR_MISMATCH", "critical", row.block_id, None, evidence, now_ms,
                      dedupe_key=f"seq:{seq}:dup:{digest.hex()}")
        if await store.put_alert(alert):
            pending.append((events.ALERT, {
                "rule": alert.rule, "severity": alert.severity, "blockId": to_hex(row.block_id),
                "ieId": None, "ts": alert.ts, "evidence": evidence,
            }))
