-- Health of the services the rules depend on (Orion, the anchor service, the DID resolver),
-- as last observed by the indexer. Store.stats() reports it next to the table counts.
CREATE TABLE service_status (
    name   text   PRIMARY KEY,
    status text   NOT NULL,
    detail text,
    at_ms  bigint NOT NULL
);

-- Rules look up existing alerts of a rule for a block (SHADOW, UNKNOWN_IE, ...).
CREATE INDEX alerts_rule_block ON alerts (rule, block_id);
CREATE INDEX alerts_rule_ie    ON alerts (rule, ie_id);
