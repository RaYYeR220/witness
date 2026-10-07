"""Write the deployment's writer policy from its identity file.

    python scripts/make_policy.py [--network testnet] [--out deploy/policy.json]

Reads deploy/identity/<network>.json (written by anchor/scripts/bootstrap-identities.ts) and
gives each aeriOS tag to the components that write it: the Trust Manager signs trust.score
itself; LLO and self-orchestrator messages come from their components or, for legacy
producers, attested by the relay; the anchor writes witness.anchor; audit reports come from
the domain, the Trust Manager or the relay. Any other tag is open (legacy traffic).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# tag -> (writer components, require_signature, legacy_grace)
RULES: dict[str, tuple[list[str], bool, bool]] = {
    "trust.score": (["trust-manager"], True, False),
    "LLO-K8s": (["llo-k8s", "relay"], False, True),
    "LLO-Docker": (["llo-k8s", "relay"], False, True),
    "self-orchestrator": (["self-orchestrator", "relay"], False, True),
    "self-security": (["relay"], False, True),
    "audit.report": (["domain", "trust-manager", "relay"], False, True),
    "witness.anchor": (["anchor"], False, True),
}


def make_policy(identity: dict) -> dict:
    dids = {e["name"]: e["did"] for e in identity.get("identities", [])}
    missing = sorted({c for writers, _, _ in RULES.values() for c in writers} - dids.keys())
    if missing:
        raise ValueError(f"identity file has no {', '.join(missing)}")
    tags = {
        tag: {"allowed": [dids[c] for c in writers], "require_signature": signed,
              "legacy_grace": grace}
        for tag, (writers, signed, grace) in RULES.items()
    }
    return {"version": 1, "tags": tags,
            "default": {"allowed": ["*"], "require_signature": False, "legacy_grace": True}}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--network", default="testnet")
    p.add_argument("--out", default=str(ROOT / "deploy" / "policy.json"))
    args = p.parse_args(argv)
    identity = json.loads((ROOT / "deploy" / "identity" / f"{args.network}.json").read_text(
        encoding="utf-8"))
    try:
        policy = make_policy(identity)
    except ValueError as e:
        print(f"make_policy: {e}", file=sys.stderr)
        return 1
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(policy, indent=2) + "\n")
    print(f"wrote {args.out}: {len(policy['tags'])} tags")
    return 0


if __name__ == "__main__":
    sys.exit(main())
