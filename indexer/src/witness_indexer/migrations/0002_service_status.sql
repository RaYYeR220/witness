-- Health of the services the rules depend on (Orion, the anchor service, the DID resolver)
-- and of the rules themselves, as last observed by the indexer. Store.stats() reports it next
-- to the table counts.
CREATE TABLE service_status (
    name   text   PRIMARY KEY,
    status text   NOT NULL,
    detail text,
    at_ms  bigint NOT NULL
);

-- Small persistent state of the rules (the R11 rotation cursor, the R14 SHADOW baseline), so
-- neither a restart nor a wiped source table silently changes what the rules judge.
CREATE TABLE rule_state (
    name  text   PRIMARY KEY,
    value jsonb  NOT NULL,
    at_ms bigint NOT NULL
);

-- R11: each anchor's verification against its record on IOTA Rebased.
ALTER TABLE anchors
    ADD COLUMN verify_state text NOT NULL DEFAULT 'unverified'
        CHECK (verify_state IN ('unverified', 'verified', 'unverifiable', 'mismatch')),
    ADD COLUMN verify_since_ms bigint,
    ADD COLUMN verify_detail   text,
    ADD COLUMN verified_at_ms  bigint;

-- Rules look up existing alerts of a rule for a block (SHADOW, UNKNOWN_IE, ...).
CREATE INDEX alerts_rule_block ON alerts (rule, block_id);
CREATE INDEX alerts_rule_ie    ON alerts (rule, ie_id);
