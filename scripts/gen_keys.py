"""Create signing keys for a new component: python scripts/gen_keys.py <component> [out_dir]."""

from __future__ import annotations

import json
import sys

from witness_sdk import keys


def main(argv: list[str]) -> int:
    if not 2 <= len(argv) <= 3:
        print(__doc__, file=sys.stderr)
        return 2
    public = keys.generate(argv[1], argv[2] if len(argv) == 3 else "secrets")
    print(json.dumps(public, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
