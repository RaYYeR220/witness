**detected 374/380 attacks (374/400 planned), 2 unexpected alerts, 0/599 false positives (20 planned trials not run: A19)**

| Class | Name | Expected | Detected | Rate | p50 | p95 |
|---|---|---|---|---|---|---|
| A01 | FORGED_SIGNATURE | FORGED | 20/20 | 100% | 5.2 s | 5.2 s |
| A02 | CROSS_TAG_REPLAY | FORGED | 20/20 | 100% | 5.2 s | 5.2 s |
| A03 | SEQ_REPLAY | REPLAY | 20/20 | 100% | 5.2 s | 5.2 s |
| A04 | UNAUTHORIZED_WRITER | UNAUTHORIZED_WRITER | 20/20 | 100% | 5.2 s | 5.5 s |
| A05 | REVOKED_KEY | REVOKED_KEY | 20/20 | 100% | 5.2 s | 5.2 s |
| A06 | ORION_DRIFT | DRIFT | 14/20 | 70% | 161.8 s | 162.4 s |
| A07 | BLOCK_BYTE_FLIP | ladder:block_hash | 20/20 | 100% | - | - |
| A08 | BAD_MERKLE_PATH | ladder:inclusion | 20/20 | 100% | - | - |
| A09 | SAMPLE_KEY_FORGED_MILESTONE | ladder:anchor | 20/20 | 100% | - | - |
| A10 | ANCHOR_MISMATCH | ladder:anchor | 20/20 | 100% | - | - |
| A11 | SEALED_WITHOUT_KEY | RELAY_ATTESTED | 20/20 | 100% | 5.2 s | 5.4 s |
| A12 | UNKNOWN_IE | UNKNOWN_IE | 20/20 | 100% | 3.7 s | 4.9 s |
| A13 | SCORE_JUMP | ANOMALY | 20/20 | 100% | 4.3 s | 4.9 s |
| A14 | STALE_IE | STALE | 20/20 | 100% | 141.9 s | 150.1 s |
| A15 | MALFORMED_PAYLOAD | MALFORMED | 20/20 | 100% | 5.2 s | 5.2 s |
| A16 | CONTENT_MISMATCH | CONTENT_MISMATCH | 20/20 | 100% | 3.6 s | 3.7 s |
| A17 | SHADOW | SHADOW | 20/20 | 100% | 59.5 s | 59.7 s |
| A18 | ORPHANED | ORPHANED | 20/20 | 100% | 60.0 s | 60.0 s |
| A19 | DB_TAMPER | DB_TAMPER | 0/0 | 0% | - | - |
| A20 | CHAIN_GAP | CHAIN_GAP | 20/20 | 100% | 4.4 s | 4.8 s |

Insertion to detection: p50 5.2 s, p95 150.2 s.

Observed outcomes of classes with misses:

- A06 ORION_DRIFT: ANOMALY x2, DRIFT x14, NONE x4

Other alerts on injected blocks (allowed side alerts are expected; unexpected ones are not):

- A01: side FORGED x20; unexpected -
- A02: side FORGED x20; unexpected -
- A03: side REPLAY x20; unexpected -
- A04: side UNAUTHORIZED_WRITER x20; unexpected -
- A05: side REVOKED_KEY x20; unexpected -
- A06: side -; unexpected ANOMALY x2
- A13: side SHADOW x5; unexpected -
- A14: side SHADOW x20; unexpected -
- A15: side MALFORMED x20; unexpected -

Not run (not counted above):

- A19: 20 trial(s), no database DSN (--db-dsn / WITNESS_CHAOS_DB)

Positive control: 20/20 relay-routed genuine blocks indexed as PRODUCER_SIGNED with no alert.

Traps: 599 genuine messages over 30 min, 0 false positives.

Bundle classes: 80/80 trials where core `bundle.verify` and the TS verifier CLI agreed on every step (genuine bundle: api).

Alerts that arrived after a trial ended (not scored):

- A01: SHADOW x20
- A02: SHADOW x20
- A03: SHADOW x20
- A04: SHADOW x20
- A05: SHADOW x20
- A06: STALE x20
- A12: SHADOW x20, STALE x20
- A13: SHADOW x35, STALE x20
- A15: SHADOW x20
- A16: STALE x20
- A17: STALE x20
- A20: STALE x20
- C01: STALE x10

Commit cd985fe2f24e8425f93911d3c8743a6a0a9815d9, config 33da8531c039e1ba, answer key 63fa160cdf480c25.
