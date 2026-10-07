**detected 20/20 attacks (20/400 planned), 0 unexpected alerts**

| Class | Name | Expected | Detected | Rate | p50 | p95 |
|---|---|---|---|---|---|---|
| A01 | FORGED_SIGNATURE | FORGED | 0/0 | 0% | - | - |
| A02 | CROSS_TAG_REPLAY | FORGED | 0/0 | 0% | - | - |
| A03 | SEQ_REPLAY | REPLAY | 0/0 | 0% | - | - |
| A04 | UNAUTHORIZED_WRITER | UNAUTHORIZED_WRITER | 0/0 | 0% | - | - |
| A05 | REVOKED_KEY | REVOKED_KEY | 0/0 | 0% | - | - |
| A06 | ORION_DRIFT | DRIFT | 0/0 | 0% | - | - |
| A07 | BLOCK_BYTE_FLIP | ladder:block_hash | 0/0 | 0% | - | - |
| A08 | BAD_MERKLE_PATH | ladder:inclusion | 0/0 | 0% | - | - |
| A09 | SAMPLE_KEY_FORGED_MILESTONE | ladder:anchor | 0/0 | 0% | - | - |
| A10 | ANCHOR_MISMATCH | ladder:anchor | 0/0 | 0% | - | - |
| A11 | SEALED_WITHOUT_KEY | RELAY_ATTESTED | 0/0 | 0% | - | - |
| A12 | UNKNOWN_IE | UNKNOWN_IE | 0/0 | 0% | - | - |
| A13 | SCORE_JUMP | ANOMALY | 0/0 | 0% | - | - |
| A14 | STALE_IE | STALE | 0/0 | 0% | - | - |
| A15 | MALFORMED_PAYLOAD | MALFORMED | 0/0 | 0% | - | - |
| A16 | CONTENT_MISMATCH | CONTENT_MISMATCH | 0/0 | 0% | - | - |
| A17 | SHADOW | SHADOW | 0/0 | 0% | - | - |
| A18 | ORPHANED | ORPHANED | 0/0 | 0% | - | - |
| A19 | DB_TAMPER | DB_TAMPER | 20/20 | 100% | 59.8 s | 60.2 s |
| A20 | CHAIN_GAP | CHAIN_GAP | 0/0 | 0% | - | - |

Insertion to detection: p50 59.8 s, p95 60.2 s.

Positive control: 20/20 relay-routed genuine blocks indexed as PRODUCER_SIGNED with no alert.

Bundle classes: 0/0 trials where core `bundle.verify` and the TS verifier CLI agreed on every step (genuine bundle: None).

Alerts that arrived after a trial ended (not scored):

- C01: STALE x10

Commit c94618cf795bc656d1932214256b0801efdeb8da, config 501b54a9c7292581, answer key 63fa160cdf480c25.
