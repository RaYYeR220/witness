"""Response and request models. JSON uses camelCase; bytes are lowercase 0x-hex; every
timestamp is given twice, as epoch milliseconds (`…Ms`) and as ISO 8601 UTC."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from pydantic.alias_generators import to_camel

METADATA_VIA = "GET /api/core/v2/blocks/{blockId}/metadata"
BLOCK_VIA = "GET /api/core/v2/blocks/{blockId}"

Verdict = Literal["PRODUCER_SIGNED", "RELAY_ATTESTED", "UNSIGNED_LEGACY", "FORGED",
                  "UNAUTHORIZED_WRITER", "REPLAY", "REVOKED_KEY", "MALFORMED"]
FlowBy = Literal["issuer", "ie", "service", "corr"]


class ApiModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


# -- messages ---------------------------------------------------------------------------------

class Message(ApiModel):
    block_id: str = Field(examples=["0x972a878cf06f2cf6b7d4a1443dbb5f12fdda376fa7537a82dad8e7257a477967"])
    tag: str | None = Field(None, examples=["trust.score"])
    kind: str | None = Field(None, examples=["trust.score"])
    verdict: str | None = Field(None, examples=["PRODUCER_SIGNED"])
    status: str | None = Field(None, description="Latest lifecycle status (RECEIVED … "
                               "CONTENT_VERIFIED)", examples=["CONTENT_VERIFIED"])
    ie_id: str | None = Field(None, examples=["MyDomain:fa163e5e25ef"])
    iss: str | None = None
    kid: str | None = None
    seq: int | None = None
    prev: str | None = None
    corr: str | None = None
    nonce: str | None = None
    encrypted: bool = False
    ms_index: int | None = Field(None, description="Milestone that confirmed the block")
    wf_index: int | None = Field(None, description="White-flag position in that milestone")
    issued_at_ms: int | None = Field(None, description="Envelope `iat`")
    issued_at: str | None = None
    milestone_at_ms: int | None = None
    milestone_at: str | None = None
    received_at_ms: int | None = Field(None, description="When the Messages API received it")
    received_at: str | None = None
    confirmed_at_ms: int | None = None
    confirmed_at: str | None = None
    date_ms: int | None = Field(None, description="The date `date_from`/`date_to` match: "
                                "received, else confirmed, else milestone time")
    date: str | None = None
    canon_hash: str | None = Field(None, description="BLAKE2b-256 of the JCS form of the body")
    content: Any = Field(None, alias="json", description="Decoded JSON body, if any")
    links: dict[str, str] = Field(default_factory=dict)


class MessagePage(ApiModel):
    items: list[Message]
    next_cursor: str | None = Field(None, description="Pass as `cursor` for the next page")
    limit: int


class Submission(ApiModel):
    sub_id: str
    source: str
    received_at_ms: int
    received_at: str
    tag: str | None = None
    message: Any = None
    data_hex: str | None = None
    hornet_status: int | None = None
    relay_verdict: str | None = None
    iss: str | None = None
    seq: int | None = None


class SolidCheck(ApiModel):
    """Brief check (c): the block is valid and solid according to the node."""

    check: Literal["c"] = "c"
    via: str = METADATA_VIA
    ok: bool | None = Field(None, description="null: not checked (yet)")
    is_solid: bool | None = None
    referenced_by_milestone_index: int | None = None
    ledger_inclusion_state: str | None = None
    checked_at_ms: int | None = None
    checked_at: str | None = None
    detail: str | None = None


class ContentCheck(ApiModel):
    """Brief check (d): the content on the Tangle is byte for byte what was received."""

    check: Literal["d"] = "d"
    via: str = BLOCK_VIA
    ok: bool | None = Field(None, description="null: not checked (yet)")
    result: Literal["MATCH", "MISMATCH", "NOT_FOUND"] | None = None
    diff: Any = None
    checked_at_ms: int | None = None
    checked_at: str | None = None
    detail: str | None = None


class Checks(ApiModel):
    solid: SolidCheck
    content: ContentCheck


class MessageDetail(Message):
    indexed: bool = Field(description="False while the block is known only from the Messages "
                          "API (not yet seen in a confirmed milestone)")
    data_hex: str | None = Field(None, description="Exact tagged-data bytes")
    submission: Submission | None = None
    checks: Checks


class Transition(ApiModel):
    status: str
    at_ms: int
    at: str
    sub_id: str | None = None
    detail: Any = None


class ValidationRow(ApiModel):
    checked_at_ms: int
    checked_at: str
    is_solid: bool
    referenced_by_milestone_index: int | None = None
    ledger_inclusion_state: str | None = None
    should_reattach: bool | None = None


class ContentCheckRow(ApiModel):
    checked_at_ms: int
    checked_at: str
    result: str
    diff: Any = None


class Lifecycle(ApiModel):
    block_id: str
    status: str | None
    transitions: list[Transition]
    validations: list[ValidationRow] = Field(description="One page of the node's metadata "
                                             "answers (newest page first, oldest first within)")
    validations_cursor: str | None = Field(None, description="Pass as `cursor` for the next, "
                                           "older page of validations")
    content_checks: list[ContentCheckRow] = Field(description="The newest 50 comparisons")
    checks: Checks
    submission: Submission | None = None


class NodeCall(ApiModel):
    request: str = Field(examples=["GET /api/core/v2/blocks/0x…/metadata"])
    outcome: Literal["answered", "not_found", "unavailable"]
    http_status: int | None = None
    size: int | None = Field(None, alias="bytes", description="Raw block size")
    error: str | None = None
    at_ms: int
    at: str
    duration_ms: int


class VerifyResult(ApiModel):
    block_id: str
    status: str | None = Field(description="Lifecycle status after the run")
    concluded: bool = Field(description="True when (c) and (d) reached an outcome")
    cached: bool = Field(description="True when the node was asked moments ago and the stored "
                         "answers are returned instead of asking again")
    timed_out: bool
    started_at_ms: int
    started_at: str
    finished_at_ms: int
    finished_at: str
    checks: Checks
    calls: list[NodeCall] = Field(description="What was asked of the node during this run")


# -- lookups ----------------------------------------------------------------------------------

class LookupResult(ApiModel):
    canon_hash: str
    body_canon_hash: str | None = Field(None, description="Set when the posted JSON is a "
                                        "witness/v1 envelope; its body is looked up too")
    matches: list[Message]


Token = Annotated[str, StringConstraints(min_length=1, max_length=256)]


class BlindQuery(ApiModel):
    tokens: list[Token] = Field(min_length=1, max_length=64, examples=[
        ["PaITfGG18DlzZ7Hde2GcHN2ty0J4yxp1muRSJ-vL14k"]])


class BlindMatch(ApiModel):
    token: str
    block_id: str
    tag: str | None = None
    kind: str | None = None
    ie_id: str | None = None
    iss: str | None = None
    verdict: str | None = None
    ms_index: int | None = None
    milestone_at_ms: int | None = None
    milestone_at: str | None = None
    links: dict[str, str]


class BlindResult(ApiModel):
    matches: list[BlindMatch]


# -- IEs, flows, incidents -----------------------------------------------------------------------

class IeSummary(ApiModel):
    ie_id: str
    count: int
    first_at_ms: int | None = None
    first_at: str | None = None
    last_at_ms: int | None = None
    last_at: str | None = None
    last_ms_index: int | None = None
    latest_score: float | None = None


class IeList(ApiModel):
    items: list[IeSummary]


class LineageEntry(ApiModel):
    block_id: str
    prev: str | None = None
    seq: int | None = None
    kind: str | None = None
    verdict: str | None = None
    ms_index: int | None = None
    wf_index: int | None = None
    at_ms: int | None = None
    at: str | None = None
    score: float | None = None
    links: dict[str, str]


class LedgerScore(ApiModel):
    score: float
    block_id: str
    verdict: str | None = None
    ms_index: int | None = None
    at_ms: int | None = None
    at: str | None = None


class OrionState(ApiModel):
    status: Literal["ok", "unknown_entity", "no_score", "unreachable", "not_configured"]
    value: float | None = None
    entity_id: str


class Lineage(ApiModel):
    ie_id: str
    entries: list[LineageEntry] = Field(description="Newest `limit` entries, oldest first")
    total: int = Field(description="Entries in the whole lineage")
    ledger: LedgerScore | None = Field(description="Latest proven score: PRODUCER_SIGNED, "
                                       "with no UNSIGNED or SHADOW alert on its block")
    orion: OrionState
    drift: bool | None = Field(description="Orion differs from the ledger by more than "
                               "`epsilon`; null when Orion cannot be compared")
    epsilon: float


class FlowSummary(ApiModel):
    key: str
    count: int
    first_at_ms: int | None = None
    first_at: str | None = None
    last_at_ms: int | None = None
    last_at: str | None = None


class FlowList(ApiModel):
    by: FlowBy
    items: list[FlowSummary]


class FlowItem(ApiModel):
    block_id: str
    prev: str | None = None
    seq: int | None = None
    tag: str | None = None
    kind: str | None = None
    verdict: str | None = None
    status: str | None = None
    iss: str | None = None
    ie_id: str | None = None
    corr: str | None = None
    ms_index: int | None = None
    wf_index: int | None = None
    at_ms: int | None = None
    at: str | None = None
    links: dict[str, str]
    claims_issuer: bool = Field(
        description="The message names `iss` but nothing proves that issuer wrote it (verdict "
                    "other than PRODUCER_SIGNED or RELAY_ATTESTED, e.g. FORGED): it is listed "
                    "in the issuer's flow but kept out of its hash chain")


class ChainView(ApiModel):
    links: int = Field(description="Proven messages whose `prev` is the issuer's previous "
                                   "proven message")
    gaps: list[str] = Field(description="Proven messages whose `prev` is not the previous "
                                        "proven message")
    forks: list[str] = Field(description="`prev` values claimed by more than one proven "
                                         "message")


class Flow(ApiModel):
    by: FlowBy
    key: str
    items: list[FlowItem] = Field(description="Newest `limit` messages, in flow order")
    total: int = Field(description="Messages in the whole flow")
    chain: ChainView | None = Field(None, description="Hash-chain view over the whole flow's "
                                    "proven messages (PRODUCER_SIGNED, RELAY_ATTESTED; issuer "
                                    "flows only)")


class Incident(ApiModel):
    id: int
    title: str
    severity: str = Field(description="Highest severity of its events and alerts",
                          examples=["high"])
    status: str = Field(description="open, closed:recovered (a proven trust score is back "
                        "where the first drop fell from) or closed:quiet (no event for 30 "
                        "minutes)", examples=["open"])
    ie_id: str | None = None
    keys: list[str] = Field(default_factory=list,
                            description="What it correlates on: ie:<IE>, sc:<service "
                                        "component>, iss:<issuer>, ledger",
                            examples=[["ie:MyDomain:fa163e5e25ef"]])
    opened_at_ms: int
    opened_at: str
    last_event_ms: int | None = None
    last_event_at: str | None = None
    closed_at_ms: int | None = None
    closed_at: str | None = None
    closed_by: str | None = Field(None, description="Block id of the trust score that closed "
                                  "it on recovery")
    baseline_score: float | None = Field(None, description="Proven trust score before the "
                                         "incident (the recovery target)")
    low_score: float | None = Field(None, description="Lowest trusted score since its first "
                                    "trust drop")


class IncidentList(ApiModel):
    items: list[Incident]


class IncidentEvent(ApiModel):
    block_id: str
    role: str = Field(description="trigger, trust-drop, security, deployment, remediation "
                      "or alert", examples=["trust-drop"])
    at_ms: int | None = Field(None, description="When it happened (relay receipt, else "
                              "confirmation)")
    at: str | None = None
    tag: str | None = None
    kind: str | None = None
    verdict: str | None = None
    status: str | None = Field(None, description="Lifecycle status of the block",
                               examples=["CONTENT_VERIFIED"])
    ms_index: int | None = None
    date_ms: int | None = None
    date: str | None = None
    indexed: bool = Field(True, description="False for a block the database has no message "
                          "for (e.g. ORPHANED)")
    detail: Any = Field(None, description="What the correlation engine saw in it")
    links: dict[str, str]


# -- alerts, anchors, identity ----------------------------------------------------------------

class AlertOut(ApiModel):
    id: int
    rule: str
    severity: str
    block_id: str | None = None
    ie_id: str | None = None
    evidence: Any = None
    at_ms: int
    at: str
    dedupe_key: str | None = None


class AlertList(ApiModel):
    items: list[AlertOut]


class IncidentDetail(Incident):
    events: list[IncidentEvent] = Field(description="A page of events in time order; check "
                                        "each against its block with links.proof")
    events_total: int = Field(0, description="Events in the whole incident")
    next_events_cursor: str | None = Field(None, description="Pass as `eventsAfter` for the "
                                           "next page of events; null on the last")
    alerts: list[AlertOut] = Field(default_factory=list,
                                   description="A page of the alerts that joined the "
                                               "incident, including those about no single "
                                               "block")
    alerts_total: int = Field(0, description="Alerts in the whole incident")
    next_alerts_after: int | None = Field(None, description="Pass as `alertsAfter` for the "
                                          "next page of alerts; null on the last")


class AnchorOut(ApiModel):
    seq: int
    from_milestone: int
    to_milestone: int
    ms_root: str | None = None
    checkpoint: Any = None
    checkpoint_hash: str | None = None
    network: str | None = None
    tx: str | None = None
    record: int | None = None
    status: str
    created_at_ms: int
    created_at: str


class AnchorList(ApiModel):
    items: list[AnchorOut]


class AnchorIdentities(ApiModel):
    status: Literal["ok", "unreachable", "not_configured"]
    network: str | None = None
    identities: list[Any] = Field(default_factory=list)
    previous: list[Any] = Field(default_factory=list)


class TagRuleOut(ApiModel):
    allowed: list[str]
    require_signature: bool
    legacy_grace: bool


class PolicySummary(ApiModel):
    version: int
    hash: str = Field(description="Policy hash committed in every checkpoint")
    tags: dict[str, TagRuleOut]
    default: TagRuleOut


class Identity(ApiModel):
    anchor: AnchorIdentities
    policy: PolicySummary | None = None


# -- chain, config, system --------------------------------------------------------------------

class MilestoneIds(ApiModel):
    from_: int = Field(alias="from")
    to: int
    ids: list[str]
    complete: bool = Field(description="False when milestones in the range are not indexed")
    msg_count: int = Field(description="Tagged-data messages referenced by the milestones of the "
                                       "range, as indexed (what a checkpoint's msgCount commits to)")


class VerifierConfigOut(ApiModel):
    bundle_version: int
    network: str
    trusted_coordinator_keys: list[str]
    threshold: int
    rebased_network: str | None = None
    trail_id: str | None = None


class NodeRouteStatus(ApiModel):
    enabled: bool
    route: str | None = None
    registered: bool = False
    error: Literal["unreachable", "rejected", "grpc_missing"] | None = Field(
        None, description="Why the last registration failed (details are in the server log)")


class ValidatorStatus(ApiModel):
    configured: bool
    running: bool
    pending: int


class Stats(ApiModel):
    counts: dict[str, int]
    # Last status each indexer component published, e.g. {"indexer": "ok", "orion":
    # "unreachable"} (see docs/operations.md).
    services: dict[str, str] = {}
    validator: ValidatorStatus
    node_route: NodeRouteStatus
    stream_subscribers: int


class Health(ApiModel):
    status: Literal["ok", "degraded"]
    db: Literal["ok", "unreachable"]
    network: str
    version: str


class IngestResult(ApiModel):
    accepted: bool
    duplicate: bool
    sub_id: str
    block_id: str | None = None
    status: str | None = None


# -- posture ----------------------------------------------------------------------------------

class Finding(ApiModel):
    id: str = Field(examples=["sample-coordinator-keys"])
    severity: Literal["high", "medium", "low", "info"]
    title: str
    evidence: Any = Field(description="What the check observed (no secrets, no node address)")
    fix: str = Field(description="Concrete, constructive remediation")


class Posture(ApiModel):
    scanned_at_ms: int | None = Field(None, description="When the cached scan ran; null if "
                                      "none has run yet")
    scanned_at: str | None = None
    active: bool = Field(False, description="True when active probes were allowed to run")
    summary: dict[str, int] = Field(default_factory=dict,
                                    description="Finding count per severity")
    findings: list[Finding] = Field(default_factory=list)


# -- reports ----------------------------------------------------------------------------------

IE_ID_PATTERN = r"^[^:\s]+:[0-9a-fA-F]{12}$"


class ReportRequest(ApiModel):
    ie: str | None = Field(None, max_length=256, pattern=IE_ID_PATTERN,
                           description="Limit to one Infrastructure Element "
                                       "(`<Domain>:<12 hex>`)",
                           examples=["MyDomain:fa163e5e25ef"])
    ms_from: int | None = Field(None, ge=0, le=0xFFFFFFFF, description="First milestone index")
    ms_to: int | None = Field(None, ge=0, le=0xFFFFFFFF, description="Last milestone index")


class ReportSummary(ApiModel):
    report_hash: str = Field(examples=["0x" + "cd" * 32])
    anchored: bool = Field(description="True once the relay accepted the audit.report "
                           "message; false means nothing on the ledger vouches for it yet")
    block_id: str | None = Field(None, description="The audit.report block, once anchored")
    ie: str | None = None
    ms_from: int | None = None
    ms_to: int | None = None
    iss: str | None = Field(None, description="DID that signed the audit.report message")
    seq: int | None = Field(None, description="Envelope sequence number claimed for it")
    generated_at_ms: int
    generated_at: str
    anchored_at_ms: int | None = None
    anchored_at: str | None = None
    links: dict[str, str] = Field(default_factory=dict)


class ReportList(ApiModel):
    items: list[ReportSummary]
    next_cursor: str | None = Field(None, description="Pass as `cursor` for the next page")
    limit: int


class ReportResult(ReportSummary):
    report: Any = Field(description="The full report JSON (its canonical form hashes to "
                        "reportHash)")
