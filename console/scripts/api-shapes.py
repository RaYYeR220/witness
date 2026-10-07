"""Writes console/src/fixtures/api/shapes.json from the witness-api response models.

For every model the console reads: its JSON field names (aliases, as the API serialises them)
and whether each is required. The console's data-layer tests hold the recorded API answers and
the console's own expectations against this file, so a model change shows up as a failing test
instead of a blank screen.

It also writes model-built examples of answers a fresh stack has none of yet (a posture scan
with findings, an anchored audit report and a lineage where Orion answered), built through the
models themselves so their shape is the API's.

Run from the repository root, in the API's environment:

    uv run python console/scripts/api-shapes.py
"""

from __future__ import annotations

import json
from pathlib import Path

from witness_api import models as m
from witness_api import reports

OUT = Path(__file__).resolve().parent.parent / "src" / "fixtures" / "api"

MODELS = [
    m.IeList, m.IeSummary, m.Lineage, m.LineageEntry, m.LedgerScore, m.OrionState,
    m.AlertList, m.AlertOut, m.IncidentList, m.Incident, m.IncidentDetail, m.IncidentEvent,
    m.AnchorList, m.AnchorOut, m.Identity, m.AnchorIdentities, m.PolicySummary, m.TagRuleOut,
    m.Posture, m.Finding, m.Stats, m.ValidatorStatus, m.NodeRouteStatus,
    m.ReportList, m.ReportSummary, m.ReportResult,
]


def shape(model: type[m.ApiModel]) -> dict[str, bool]:
    return {(f.alias or name): f.is_required() for name, f in model.model_fields.items()}


def dump(model: m.ApiModel) -> dict:
    return model.model_dump(by_alias=True, mode="json")


BLOCK = "0x" + "ab" * 32
GEN_MS = 1791331200000

posture = m.Posture(
    scanned_at_ms=GEN_MS, scanned_at="2026-10-07T00:00:00.000Z", active=False,
    summary={"high": 1, "low": 1},
    findings=[
        m.Finding(id="sample-coordinator-keys", severity="high",
                  title="The node trusts the sample coordinator keys",
                  evidence={"keys": ["0xed3c…248c"], "source": "protocol config"},
                  fix="Generate a coordinator key pair for this network and pin its public key."),
        m.Finding(id="dashboard-exposed", severity="low", title="The node dashboard answers",
                  evidence={"status": 200, "path": "/dashboard/"},
                  fix="Bind the dashboard to localhost or put it behind the operator's login."),
    ])

report_body = {
    "v": reports.VERSION, "kind": reports.KIND, "network": "private_tangle1",
    "generatedAt": GEN_MS, "range": {"msFrom": 1, "msTo": 1440}, "ie": None,
    "messages": {"total": 318, "encrypted": 0, "plaintext": 318, "confirmed": 318,
                 "byVerdict": {"PRODUCER_SIGNED": 172, "UNSIGNED_LEGACY": 146}},
    "alerts": {"total": 2, "bySeverity": {"medium": 2}, "byRule": {"UNSIGNED": 2}},
    "anchors": {"total": 2, "byStatus": {"anchored": 2},
                "latest": {"seq": 2, "fromMilestone": 721, "toMilestone": 1440,
                           "status": "anchored", "network": "testnet", "record": 2,
                           "tx": "5K3CqSHNQR7t3yuuUqjZYxk2cRmDPwtPHuHYQhy7coj5"}},
    "proofs": [{"blockId": BLOCK, "tag": "trust.score", "kind": "trust.score",
                "ieId": "MyDomain:fa163e5e25ef", "iss": None, "verdict": "PRODUCER_SIGNED",
                "msIndex": 1433, "wfIndex": 3, "proof": f"/proofs/{BLOCK}"}],
    "proofsTruncated": True,
}
HASH = "0x" + reports.report_hash(report_body).hex()
report = m.ReportResult(
    report_hash=HASH, anchored=True, block_id=BLOCK, ie=None, ms_from=1, ms_to=1440,
    iss="did:iota:testnet:0x6b9a693ebf2ac6fb771a75d25b1284ba75aeb0ae16618eaf5d41d24828a6f7a2",
    seq=GEN_MS, generated_at_ms=GEN_MS, generated_at="2026-10-07T00:00:00.000Z",
    anchored_at_ms=GEN_MS + 4000, anchored_at="2026-10-07T00:00:04.000Z",
    links={"self": f"/reports/{HASH}", "html": f"/reports/{HASH}.html"}, report=report_body)
report_list = m.ReportList(items=[m.ReportSummary(**report.model_dump(exclude={"report"}))],
                           next_cursor=None, limit=50)

lineage = m.Lineage(
    ie_id="MyDomain:fa163e5e25ef",
    entries=[m.LineageEntry(block_id="0x" + f"{i:02x}" * 32, seq=GEN_MS + i, kind="trust.score",
                            verdict="PRODUCER_SIGNED", ms_index=1400 + i, wf_index=1,
                            at_ms=GEN_MS + i * 60000, at=None, score=s,
                            links={"self": "/messages/0x" + f"{i:02x}" * 32})
             for i, s in enumerate([0.82, 0.8, 0.41, 0.43], start=1)],
    total=4,
    ledger=m.LedgerScore(score=0.43, block_id="0x" + "04" * 32, verdict="PRODUCER_SIGNED",
                         ms_index=1404, at_ms=GEN_MS + 240000),
    orion=m.OrionState(status="ok", value=0.82,
                       entity_id="urn:ngsi-ld:InfrastructureElement:MyDomain:fa163e5e25ef"),
    drift=True, epsilon=0.01)

OUT.mkdir(parents=True, exist_ok=True)
shapes = {"about": "JSON field names of the witness-api response models (true = required), "
                   "written by console/scripts/api-shapes.py",
          "models": {model.__name__: shape(model) for model in MODELS}}
(OUT / "shapes.json").write_text(json.dumps(shapes, indent=1) + "\n", encoding="utf-8")
examples = {"about": "Answers built through the witness-api models (console/scripts/api-shapes.py) "
                     "for states a fresh stack has none of yet. Values are illustrative.",
            "posture": dump(posture), "reports": dump(report_list), "report": dump(report),
            "lineageOrionOk": dump(lineage)}
(OUT / "examples.json").write_text(json.dumps(examples, indent=1) + "\n", encoding="utf-8")
print(f"wrote {OUT / 'shapes.json'} and {OUT / 'examples.json'}")
