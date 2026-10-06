"""`python -m witness_sdk`: read one JSON request on stdin, upload it, print the reply.

Request: {"relay_url", "node", "tag", "body", "commitments"?, "meta"?}. The signer comes
from the environment (WITNESS_KEY_PATH [+ WITNESS_KID, WITNESS_ISS] or WITNESS_COMPONENT +
WITNESS_SECRETS_DIR; WITNESS_STATE_PATH; WITNESS_DISCLOSURES_PATH for the salts log). It
lets a service on an older interpreter sign through a separate Python. Failures are
printed as {"error": ...} with exit code 1.
"""

from __future__ import annotations

import json
import os
import sys

from .signer import signer_from_env


def main() -> int:
    try:
        req = json.load(sys.stdin)
        signer = signer_from_env(os.environ)
        if signer is None:
            raise RuntimeError("no signing key configured")
        reply = signer.upload(
            req["relay_url"],
            req["node"],
            req["tag"],
            req["body"],
            req.get("commitments"),
            disclosures_path=os.environ.get("WITNESS_DISCLOSURES_PATH") or None,
            meta=req.get("meta"),
        )
    except Exception as exc:  # noqa: BLE001 - the caller parses stdout, so report as JSON
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        return 1
    print(json.dumps(reply))
    return 0 if reply.get("http_status") == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
