-- Signed audit reports produced by the API (POST /reports). Each report is stored as its
-- canonical JSON and a rendered HTML page; its BLAKE2b-256 (canon_hash of the JSON) is the
-- primary key and is what gets written back to the Tangle as an `audit.report` message.
--
-- Two phases: a report is stored with `anchored = false` before it is posted, and marked
-- anchored with its block id only once the relay has accepted it, so a report whose post
-- failed is never mistaken for an anchored one. `iss`/`seq` record the envelope sequence
-- number claimed for the post; the next post continues above the highest one.

CREATE TABLE reports (
    report_hash     bytea   PRIMARY KEY,
    ie              text,
    ms_from         bigint,
    ms_to           bigint,
    json            jsonb   NOT NULL,
    html            text    NOT NULL,
    anchored        boolean NOT NULL DEFAULT false,
    block_id        bytea,
    iss             text,
    seq             bigint,
    generated_at_ms bigint  NOT NULL,
    created_at_ms   bigint  NOT NULL,
    anchored_at_ms  bigint,
    CHECK (NOT anchored OR block_id IS NOT NULL)
);
CREATE INDEX reports_generated ON reports (generated_at_ms DESC, report_hash DESC);
CREATE INDEX reports_iss_seq   ON reports (iss, seq);
