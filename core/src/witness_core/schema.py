"""Schema registry for the tagged-data messages aeriOS components write.

`classify` maps the block tag to a message kind and checks the JSON against
that kind's shape. witness/v1 envelopes are unwrapped first and their `body`
is what gets checked; a sealed (encrypted) body cannot be inspected and counts
as well formed. Extra fields are allowed; required ones must have the right type.
Never raises.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any

from . import checkpoint, envelope

KINDS: dict[str, str] = {
    "trust.score": "trust.score",
    "LLO-K8s": "llo.k8s",
    "LLO-Docker": "llo.docker",
    "self-orchestrator": "self-orchestrator",
    "witness.anchor": "witness.anchor",
    "audit.report": "audit.report",
}
UNKNOWN = "unknown"

# Trust Manager ids are "<Domain>:<IE MAC without colons>".
_IE_ID = re.compile(r"[^:\s]+:[0-9a-fA-F]{12}")
_IE_URN = "urn:ngsi-ld:InfrastructureElement:"
_H32 = re.compile(r"0x[0-9a-f]{64}")
_MAX_INT = 2**53 - 1


@dataclass(frozen=True)
class Classified:
    kind: str
    json: Any | None
    ie_id: str | None
    envelope: dict | None
    schema_ok: bool
    nonce: str | None = None
    prev: str | None = None
    corr: str | None = None


class _NotJson:
    pass


_NOT_JSON = _NotJson()


def _parse(data: bytes) -> Any:
    def reject(token: str) -> Any:
        raise ValueError(f"non-finite number {token}")

    try:
        return json.loads(data.decode("utf-8"), parse_constant=reject)
    except (ValueError, RecursionError):  # includes UnicodeDecodeError, JSONDecodeError
        return _NOT_JSON


def _text(v: Any) -> bool:
    return isinstance(v, str) and v != ""


def _number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _uint(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= _MAX_INT


def _h32(v: Any) -> bool:
    return isinstance(v, str) and _H32.fullmatch(v) is not None


def _trust_score(m: dict) -> tuple[bool, str | None]:
    ie = m.get("id")
    ie_ok = isinstance(ie, str) and _IE_ID.fullmatch(ie) is not None
    score = m.get("score")
    score_ok = _number(score) and 0 <= score <= 1
    return ie_ok and score_ok, ie if ie_ok else None


def _llo(m: dict) -> tuple[bool, str | None]:
    return all(_text(m.get(k)) for k in ("event", "lloId", "serviceComponentId")), None


def _self_orchestrator(m: dict) -> tuple[bool, str | None]:
    ie = m.get("infrastructureElementId")
    code = m.get("errorCode")
    code_ok = _text(code) or (isinstance(code, int) and not isinstance(code, bool))
    if not _text(ie):
        return False, None
    # Orion entity ids carry a URN prefix; strip it so ids line up with trust.score.
    norm = ie[len(_IE_URN):] if ie.startswith(_IE_URN) and len(ie) > len(_IE_URN) else ie
    return code_ok, norm


def _witness_anchor(m: dict) -> tuple[bool, str | None]:
    cp = m.get("checkpoint")
    if checkpoint.shape_error(cp) is not None or not _h32(m.get("checkpointHash")):
        return False, None
    if "0x" + checkpoint.hash(cp).hex() != m["checkpointHash"]:
        return False, None
    rebased = m.get("rebased")
    ok = (
        isinstance(rebased, dict)
        and all(_text(rebased.get(k)) for k in ("network", "trail", "tx"))
        and _uint(rebased.get("record"))
    )
    return ok, None


def _audit_report(m: dict) -> tuple[bool, str | None]:
    return _h32(m.get("reportHash")), None


_CHECKS = {
    "trust.score": _trust_score,
    "llo.k8s": _llo,
    "llo.docker": _llo,
    "self-orchestrator": _self_orchestrator,
    "witness.anchor": _witness_anchor,
    "audit.report": _audit_report,
}


def _check(kind: str, obj: Any) -> tuple[bool, str | None]:
    check = _CHECKS.get(kind)
    if check is None:
        return True, None
    if not isinstance(obj, dict):
        return False, None
    return check(obj)


def _opt_str(v: Any) -> str | None:
    return v if isinstance(v, str) else None


def classify(tag: str, data: bytes) -> Classified:
    obj = _parse(data)
    if obj is _NOT_JSON:
        return Classified(UNKNOWN, None, None, None, False)
    kind = KINDS.get(tag, UNKNOWN)
    if not envelope.is_envelope(obj):
        ok, ie_id = _check(kind, obj)
        return Classified(kind, obj, ie_id, None, ok)
    env = obj
    meta = (_opt_str(env.get("nonce")), _opt_str(env.get("prev")), _opt_str(env.get("corr")))
    if "enc" in env:
        sealed_ok = "body" not in env and isinstance(env["enc"], dict)
        return Classified(kind, None, None, env, sealed_ok, *meta)
    body = env.get("body")
    if not isinstance(body, dict):
        return Classified(kind, None, None, env, False, *meta)
    ok, ie_id = _check(kind, body)
    return Classified(kind, body, ie_id, env, ok, *meta)
