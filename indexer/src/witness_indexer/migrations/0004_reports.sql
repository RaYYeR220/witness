-- Signed audit reports produced by the API (POST /reports). Each report is stored as its
-- canonical JSON and a rendered HTML page; its BLAKE2b-256 (canon_hash of the JSON) is the
-- primary key and is what gets written back to the Tangle as an `audit.report` message.

CREATE TABLE reports (
    report_hash     bytea  PRIMARY KEY,
    ie              text,
    ms_from         bigint,
    ms_to           bigint,
    json            jsonb  NOT NULL,
    html            text   NOT NULL,
    block_id        bytea,
    generated_at_ms bigint NOT NULL,
    created_at_ms   bigint NOT NULL
);
CREATE INDEX reports_generated ON reports (generated_at_ms DESC);
