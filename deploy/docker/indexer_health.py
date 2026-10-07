"""Container health check of the indexer (it serves no HTTP).

Healthy when the database answers, the indexer has not given up on a milestone (`stuck at N`,
`network changed`) and the newest indexed milestone is at most WITNESS_HEALTH_MAX_LAG_S
seconds old (default 120; the private Tangle issues one every ~5 s). Exit 0 healthy, 1 not.
"""

from __future__ import annotations

import os
import sys
import time

import psycopg
from psycopg import sql


def main() -> int:
    dsn = os.environ.get("WITNESS_DB")
    if not dsn:
        print("WITNESS_DB is not set")
        return 1
    schema = os.environ.get("WITNESS_SCHEMA") or "witness"
    max_lag = float(os.environ.get("WITNESS_HEALTH_MAX_LAG_S") or 120)
    try:
        with psycopg.connect(dsn, connect_timeout=5) as conn:
            newest = conn.execute(
                sql.SQL("SELECT max(ts) FROM {}.milestones").format(sql.Identifier(schema))
            ).fetchone()[0]
            row = conn.execute(
                sql.SQL("SELECT status FROM {}.service_status WHERE name = 'indexer'").format(
                    sql.Identifier(schema))
            ).fetchone()
    except psycopg.Error as e:
        print(f"database: {type(e).__name__}")
        return 1
    status = row[0] if row else "starting"
    if status.startswith(("stuck", "network changed")):
        print(f"indexer: {status}")
        return 1
    if newest is None:
        print("no milestone indexed yet")
        return 1
    lag = time.time() - newest
    if lag > max_lag:
        print(f"newest indexed milestone is {lag:.0f} s old (indexer: {status})")
        return 1
    print(f"ok: newest milestone {lag:.0f} s old (indexer: {status})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
