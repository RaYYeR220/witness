"""Shared helpers for the chaos tests."""

from witness_chaos import scorecard

# Raised by the validator (see indexer validator source), not listed in rules.SEVERITY.
VALIDATOR_ALERTS = {"ORPHANED": "high", "CONTENT_MISMATCH": "critical",
                    "DB_TAMPER": "critical", "NOT_FOUND": "critical"}


def control_ok(trial=0, **over):
    """A C01 control row that passes: indexed, PRODUCER_SIGNED, no alert."""
    return {"control": "C01", "trial": trial, "status": "ok", "blockId": f"0x{trial:064x}",
            "indexed": True, "verdict": "PRODUCER_SIGNED", "alerts": [], **over}


CONTROLS_OK = [control_ok(0), control_ok(1)]


def cls(key, cid):
    return next(c for c in key["classes"] if c["id"] == cid)


def make(key, misses=None, wrong=None):
    """Synthetic trial results: every trial detected except the first `misses`/`wrong`."""
    misses, wrong = misses or {}, wrong or {}
    out = []
    for c in key["classes"]:
        label = scorecard.expected_label(c["expect"])
        for t in range(c["trials"]):
            if t < misses.get(c["id"], 0):
                out.append({"class": c["id"], "trial": t, "detected": False, "observed": None})
            elif t < misses.get(c["id"], 0) + wrong.get(c["id"], 0):
                out.append({"class": c["id"], "trial": t, "detected": False,
                            "observed": "PRODUCER_SIGNED"})
            else:
                out.append({"class": c["id"], "trial": t, "detected": True, "observed": label,
                            "latency_ms": 1000 * (t + 1)})
    return out
