"""Scoring of a fault-injection run: pure functions over trial results.

A trial result is a dict:
  {"class": "A01", "trial": 3, "detected": True, "observed": "FORGED",
   "latency_ms": 4200}
`detected` means the expected verdict/alert/ladder outcome was seen in time;
`observed` is what the explorer actually showed for the injected block (None when
nothing showed up). Trap results describe genuine traffic:
  {"messages": 512, "duration_s": 1900, "alerts": 0, "verdicts": {"PRODUCER_SIGNED": 300}}
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable

NONE = "NONE"
SCHEMA = "witness-chaos/scorecard/v1"


def percentile(values: Iterable[float], p: float) -> float | None:
    """Nearest-rank percentile, p in (0, 100]; None for no data."""
    data = sorted(values)
    if not data:
        return None
    rank = max(1, math.ceil(p / 100 * len(data)))
    return data[rank - 1]


def expected_label(expect: dict) -> str:
    if "verdict" in expect:
        return expect["verdict"]
    if "alert" in expect:
        return expect["alert"]
    if "ladder" in expect:
        return f"ladder:{expect['ladder']['step']}"
    return f"ladder_overall:{expect['ladder_overall']}"


def alert_buckets(cls: dict, alerts: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split the alerts seen on an injected block into (allowed side alerts, unexpected).

    The alert the class expects is neither: it is the detection itself.
    """
    expected = cls["expect"].get("alert")
    allowed = set(cls.get("allowed_side_alerts", []))
    side, unexpected = [], []
    for a in alerts:
        if a == expected:
            continue
        (side if a in allowed else unexpected).append(a)
    return side, unexpected


def evaluate_trial(cls: dict, obs: dict) -> dict:
    """Score one trial from what was observed on the injected block.

    obs: {"verdict": str|None, "alerts": [rule, ...], "ladder": {step: ok}, "overall": str,
          "parses": bool|None, "sealed": bool|None, "blind_search": bool|None}
    Every assertion in the class's `expect` must hold for the trial to count as detected.
    """
    e = cls["expect"]
    alerts = list(obs.get("alerts", []))
    checks: list[bool] = []
    if "verdict" in e:
        checks.append(obs.get("verdict") == e["verdict"])
    if "alert" in e:
        checks.append(e["alert"] in alerts)
    if "ladder" in e:
        want = e["ladder"]
        checks.append((obs.get("ladder") or {}).get(want["step"]) is want["ok"])
        if "parses" in want:
            checks.append(obs.get("parses") is want["parses"])
    if "ladder_overall" in e:
        checks.append(obs.get("overall") == e["ladder_overall"])
    if "block_verdict" in e:
        checks.append(obs.get("verdict") == e["block_verdict"])
    for flag in ("sealed", "blind_search"):
        if e.get(flag):
            checks.append(obs.get(flag) is True)
    detected = bool(checks) and all(checks)
    if detected:
        observed = expected_label(e)
    else:
        observed = obs.get("verdict") or (alerts[0] if alerts else None)
    return {"detected": detected, "observed": observed, "alerts": alerts}


def control_passed(control: dict, alerts: Iterable[str]) -> bool:
    """A positive control passes when the forbidden alert (and any alert, if the control
    says `alerts: 0`) is absent."""
    seen = list(alerts)
    e = control["expect"]
    if "no_alert" in e and e["no_alert"] in seen:
        return False
    return not (e.get("alerts") == 0 and seen)


def confusion_matrix(results: list[dict], classes: list[dict]) -> dict[str, dict[str, int]]:
    """Per class: how many trials ended in each observed outcome (NONE = nothing seen)."""
    matrix: dict[str, Counter] = {c["id"]: Counter() for c in classes}
    for r in results:
        if r["class"] not in matrix:
            raise KeyError(f"result for unknown class {r['class']}")
        matrix[r["class"]][r.get("observed") or NONE] += 1
    return {k: dict(v) for k, v in matrix.items()}


def per_class(results: list[dict], classes: list[dict]) -> list[dict]:
    matrix = confusion_matrix(results, classes)
    out = []
    for c in classes:
        mine = [r for r in results if r["class"] == c["id"]]
        hit = [r for r in mine if r.get("detected")]
        side: Counter = Counter()
        unexpected: Counter = Counter()
        for r in mine:
            s_, u_ = alert_buckets(c, r.get("alerts", []))
            side.update(s_)
            unexpected.update(u_)
        lat = [r["latency_ms"] for r in hit if r.get("latency_ms") is not None]
        out.append({
            "id": c["id"], "name": c["name"], "expected": expected_label(c["expect"]),
            "trials": len(mine), "planned": c.get("trials", len(mine)),
            "detected": len(hit),
            "rate": len(hit) / len(mine) if mine else 0.0,
            "observed": matrix[c["id"]],
            "side_alerts": dict(side), "unexpected_alerts": dict(unexpected),
            "latency_p50_ms": percentile(lat, 50), "latency_p95_ms": percentile(lat, 95),
        })
    return out


def trap_false_positives(trap: dict, allowed_verdicts: Iterable[str]) -> int:
    """Alerts raised on genuine traffic plus messages with a verdict outside the allowed set."""
    allowed = set(allowed_verdicts)
    bad = sum(n for v, n in trap.get("verdicts", {}).items() if v not in allowed)
    return int(trap.get("alerts", 0)) + bad


def build_scorecard(results: list[dict], trap: dict | None, key: dict,
                    control_results: list[dict] | None = None,
                    not_run: list[dict] | None = None) -> dict:
    """`not_run`: [{"class", "trials", "reason"}] for planned trials that were never
    injected (missing setup, injection errors). They are not in the denominator, but the
    headline and the markdown say so."""
    classes = key["classes"]
    rows = per_class(results, classes)
    detected = sum(r["detected"] for r in rows)
    total = sum(r["trials"] for r in rows)
    lat = [x["latency_ms"] for x in results
           if x.get("detected") and x.get("latency_ms") is not None]
    card: dict = {
        "schema": SCHEMA,
        "classes": rows,
        "detected": detected,
        "attacks": total,
        "planned_attacks": sum(c.get("trials", 0) for c in classes),
        "detection_rate": detected / total if total else 0.0,
        "latency_p50_ms": percentile(lat, 50),
        "latency_p95_ms": percentile(lat, 95),
        "unexpected_alerts": sum(sum(r["unexpected_alerts"].values()) for r in rows),
        "traps": None,
        "controls": None,
        "not_run": list(not_run or []),
    }
    if control_results is not None:
        by_id = {c["id"]: c for c in key.get("controls", [])}
        passed = sum(control_passed(by_id[r["control"]], r.get("alerts", []))
                     for r in control_results)
        card["controls"] = {"trials": len(control_results), "passed": passed}
    if trap is not None:
        spec = key["traps"]["expect"]
        fp = trap_false_positives(trap, spec["verdicts"])
        card["traps"] = {
            "messages": trap.get("messages", 0),
            "duration_s": trap.get("duration_s", 0),
            "min_messages": key["traps"]["min_messages"],
            "min_duration_s": key["traps"]["duration_min"] * 60,
            "false_positives": fp,
            "verdicts": trap.get("verdicts", {}),
            "meets_profile": (trap.get("messages", 0) >= key["traps"]["min_messages"]
                              and trap.get("duration_s", 0) >= key["traps"]["duration_min"] * 60),
        }
    card["headline"] = headline(card)
    return card


def headline(card: dict) -> str:
    text = f"detected {card['detected']}/{card['attacks']} attacks"
    if card.get("traps"):
        t = card["traps"]
        text += f", {t['false_positives']}/{t['messages']} false positives"
    skipped = card.get("not_run") or []
    if skipped:
        n = sum(s.get("trials", 0) for s in skipped)
        classes = sorted({s["class"] for s in skipped})
        text += f" ({n} planned trials not run: {', '.join(classes)})"
    return text


def _ms(v: float | None) -> str:
    return "-" if v is None else f"{v / 1000:.1f} s"


def render_markdown(card: dict) -> str:
    lines = [f"**{card['headline']}**", "",
             "| Class | Name | Expected | Detected | Rate | p50 | p95 |",
             "|---|---|---|---|---|---|---|"]
    for r in card["classes"]:
        lines.append(
            f"| {r['id']} | {r['name']} | {r['expected']} | {r['detected']}/{r['trials']} "
            f"| {r['rate']:.0%} | {_ms(r['latency_p50_ms'])} | {_ms(r['latency_p95_ms'])} |")
    p50, p95 = _ms(card["latency_p50_ms"]), _ms(card["latency_p95_ms"])
    lines += ["", f"Insertion to detection: p50 {p50}, p95 {p95}."]
    misses = [r for r in card["classes"] if r["detected"] < r["trials"]]
    if misses:
        lines += ["", "Observed outcomes of classes with misses:", ""]
        for r in misses:
            seen = ", ".join(f"{k} x{v}" for k, v in sorted(r["observed"].items()))
            lines.append(f"- {r['id']} {r['name']}: {seen}")
    noisy = [r for r in card["classes"] if r["side_alerts"] or r["unexpected_alerts"]]
    if noisy:
        lines += ["", ("Other alerts on injected blocks (allowed side alerts are expected; "
                       "unexpected ones are not):"), ""]
        for r in noisy:
            side = ", ".join(f"{k} x{v}" for k, v in sorted(r["side_alerts"].items())) or "-"
            bad = ", ".join(f"{k} x{v}" for k, v in sorted(r["unexpected_alerts"].items())) or "-"
            lines.append(f"- {r['id']}: side {side}; unexpected {bad}")
    skipped = card.get("not_run") or []
    if skipped:
        lines += ["", "Not run (not counted above):", ""]
        for s in skipped:
            lines.append(f"- {s['class']}: {s.get('trials', 0)} trial(s), {s['reason']}")
    c = card.get("controls")
    if c:
        lines += ["", (f"Positive control: {c['passed']}/{c['trials']} relay-routed genuine "
                       "blocks raised no alert.")]
    t = card.get("traps")
    if t:
        lines += ["", f"Traps: {t['messages']} genuine messages over "
                      f"{t['duration_s'] / 60:.0f} min, {t['false_positives']} false positives"
                      + ("" if t["meets_profile"] else " (below the pre-registered profile)")
                      + "."]
    return "\n".join(lines) + "\n"
