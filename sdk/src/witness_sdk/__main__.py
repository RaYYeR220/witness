"""`python -m witness_sdk`: read one JSON request on stdin, upload it, print the reply.

Request: {"relay_url", "node", "tag", "body", "commitments"?}. The signer comes from the
environment (WITNESS_KEY_PATH [+ WITNESS_KID, WITNESS_ISS] or WITNESS_COMPONENT +
WITNESS_SECRETS_DIR; WITNESS_STATE_PATH). It lets a service on an older interpreter sign
through a separate Python.
"""

from __future__ import annotations

import json
import os
import sys

from .signer import signer_from_env


def main() -> int:
    req = json.load(sys.stdin)
    signer = signer_from_env(os.environ)
    if signer is None:
        print(json.dumps({"error": "no signing key configured"}))
        return 2
    reply = signer.upload(
        req["relay_url"], req["node"], req["tag"], req["body"], req.get("commitments")
    )
    print(json.dumps(reply))
    return 0 if reply.get("http_status") == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
