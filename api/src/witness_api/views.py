"""Store rows -> API models: hex for bytes, `…Ms` + ISO 8601 for every timestamp."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from . import models as m


def hx(b: bytes | memoryview | None) -> str | None:
    return None if b is None else "0x" + bytes(b).hex()


def iso(ms: int | None) -> str | None:
    """Epoch milliseconds as ISO 8601 UTC with millisecond precision; None when the value is
    outside what a calendar date can express (a signed `iat` may be any 53-bit integer)."""
    if ms is None:
        return None
    whole, frac = divmod(int(ms), 1000)
    try:
        moment = datetime.fromtimestamp(whole, UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return moment.strftime("%Y-%m-%dT%H:%M:%S") + f".{frac:03d}Z"


def sec_to_ms(ts: int | None) -> int | None:
    """Milestone timestamps are seconds; 0 means "not confirmed yet"."""
    return int(ts) * 1000 if ts else None


class Linker:
    """Builds links to API resources, absolute when a public base URL is configured."""

    def __init__(self, base: str | None) -> None:
        self.base = (base or "").rstrip("/")

    def __call__(self, path: str) -> str:
        return self.base + path

    def message(self, block_id: str) -> dict[str, str]:
        return {"self": self(f"/messages/{block_id}"),
                "lifecycle": self(f"/messages/{block_id}/lifecycle"),
                "proof": self(f"/proofs/{block_id}")}


def message(row: dict, link: Linker) -> m.Message:
    bid = hx(row["block_id"])
    ms_at = sec_to_ms(row.get("ts"))
    date = row.get("received_at_ms") or row.get("confirmed_at_ms") or ms_at
    return m.Message(
        block_id=bid, tag=row.get("tag"), kind=row.get("kind"), verdict=row.get("verdict"),
        status=row.get("status"), ie_id=row.get("ie_id"), iss=row.get("iss"),
        kid=row.get("kid"), seq=row.get("seq"), prev=hx(row.get("prev")), corr=row.get("corr"),
        nonce=row.get("nonce"), encrypted=bool(row.get("encrypted")),
        ms_index=row.get("ms_index"), wf_index=row.get("wf_index"),
        issued_at_ms=row.get("iat"), issued_at=iso(row.get("iat")),
        milestone_at_ms=ms_at, milestone_at=iso(ms_at),
        received_at_ms=row.get("received_at_ms"), received_at=iso(row.get("received_at_ms")),
        confirmed_at_ms=row.get("confirmed_at_ms"),
        confirmed_at=iso(row.get("confirmed_at_ms")),
        date_ms=date, date=iso(date), canon_hash=hx(row.get("canon_hash")),
        content=row.get("json"), links=link.message(bid),
    )


def submission(row: dict | None) -> m.Submission | None:
    if row is None:
        return None
    return m.Submission(
        sub_id=row["sub_id"], source=row["source"], received_at_ms=row["received_at_ms"],
        received_at=iso(row["received_at_ms"]), tag=row["tag"], message=row["message_json"],
        data_hex=row["data_hex"], hornet_status=row["hornet_status"],
        relay_verdict=row["relay_verdict"], iss=row["iss"], seq=row["seq"])


def solid_ok(is_solid: bool | None, state: str | None) -> bool | None:
    if is_solid is None:
        return None
    return bool(is_solid) and state != "conflicting"


def checks(validations: list[dict], content: list[dict]) -> m.Checks:
    """The brief's checks (c) and (d) as they stand after the latest stored answers."""
    solid = m.SolidCheck(detail="not checked yet")
    if validations:
        v = validations[-1]
        solid = m.SolidCheck(
            ok=solid_ok(v["is_solid"], v["ledger_inclusion_state"]), is_solid=v["is_solid"],
            referenced_by_milestone_index=v["referenced_by_ms"],
            ledger_inclusion_state=v["ledger_inclusion_state"],
            checked_at_ms=v["checked_at_ms"], checked_at=iso(v["checked_at_ms"]))
    found = m.ContentCheck(detail="not checked yet")
    if content:
        c = content[-1]
        found = m.ContentCheck(ok=c["result"] == "MATCH", result=c["result"], diff=c["diff"],
                               checked_at_ms=c["checked_at_ms"],
                               checked_at=iso(c["checked_at_ms"]))
    return m.Checks(solid=solid, content=found)


def transition(row: dict) -> m.Transition:
    return m.Transition(status=row["status"], at_ms=row["at_ms"], at=iso(row["at_ms"]),
                        sub_id=row["sub_id"], detail=row["detail"])


def validation(row: dict) -> m.ValidationRow:
    return m.ValidationRow(
        checked_at_ms=row["checked_at_ms"], checked_at=iso(row["checked_at_ms"]),
        is_solid=row["is_solid"], referenced_by_milestone_index=row["referenced_by_ms"],
        ledger_inclusion_state=row["ledger_inclusion_state"],
        should_reattach=row["should_reattach"])


def content_check(row: dict) -> m.ContentCheckRow:
    return m.ContentCheckRow(checked_at_ms=row["checked_at_ms"],
                             checked_at=iso(row["checked_at_ms"]), result=row["result"],
                             diff=row["diff"])


def alert(row: dict) -> m.AlertOut:
    return m.AlertOut(id=row["id"], rule=row["rule"], severity=row["severity"],
                      block_id=hx(row["block_id"]), ie_id=row["ie_id"],
                      evidence=row["evidence"], at_ms=row["ts"], at=iso(row["ts"]),
                      dedupe_key=row["dedupe_key"])


def anchor(row: dict) -> m.AnchorOut:
    return m.AnchorOut(
        seq=row["seq"], from_milestone=row["from_ms"], to_milestone=row["to_ms"],
        ms_root=hx(row["ms_root"]), checkpoint=row["checkpoint"],
        checkpoint_hash=hx(row["checkpoint_hash"]), network=row["network"], tx=row["tx"],
        record=row["record"], status=row["status"], created_at_ms=row["created_at_ms"],
        created_at=iso(row["created_at_ms"]))


def incident(row: dict) -> dict[str, Any]:
    return {"id": row["id"], "title": row["title"], "severity": row["severity"],
            "status": row["status"], "ie_id": row["ie_id"],
            "opened_at_ms": row["opened_at_ms"], "opened_at": iso(row["opened_at_ms"]),
            "closed_at_ms": row["closed_at_ms"], "closed_at": iso(row["closed_at_ms"])}
