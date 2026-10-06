-- Witness store, initial schema. Applied inside the target schema (search_path is set).

CREATE TABLE milestones (
    idx            bigint PRIMARY KEY,
    id             bytea  NOT NULL UNIQUE,
    ts             bigint NOT NULL,
    essence        bytea  NOT NULL,
    sigs           jsonb  NOT NULL DEFAULT '[]',
    inclusion_root bytea  NOT NULL,
    prev_id        bytea  NOT NULL
);

CREATE TABLE blocks (
    id           bytea PRIMARY KEY,
    ms_index     bigint NOT NULL,
    wf_index     integer NOT NULL,
    raw          bytea NOT NULL,
    payload_type integer NOT NULL
);
CREATE INDEX blocks_cone ON blocks (ms_index, wf_index);

CREATE TABLE messages (
    block_id        bytea PRIMARY KEY,
    tag             text,
    kind            text,
    data            bytea,
    json            jsonb NOT NULL DEFAULT '{}',
    ie_id           text,
    canon_hash      bytea,
    iss             text,
    kid             text,
    seq             bigint,
    iat             bigint,
    verdict         text,
    encrypted       boolean NOT NULL DEFAULT false,
    ms_index        bigint,
    wf_index        integer,
    ts              bigint NOT NULL DEFAULT 0,
    prev            bytea,
    corr            text,
    status          text,
    received_at_ms  bigint,
    confirmed_at_ms bigint,
    tsv             tsvector GENERATED ALWAYS AS (to_tsvector('simple', json::text)) STORED
);
CREATE INDEX messages_json_gin ON messages USING gin (json);
CREATE INDEX messages_tsv_gin  ON messages USING gin (tsv);
CREATE INDEX messages_tag      ON messages (tag);
CREATE INDEX messages_ie       ON messages (ie_id);
CREATE INDEX messages_iss_seq  ON messages (iss, seq);
CREATE INDEX messages_corr     ON messages (corr);
CREATE INDEX messages_canon    ON messages (canon_hash);
CREATE INDEX messages_ms       ON messages (ms_index DESC, wf_index DESC);

CREATE TABLE blind_index (
    token    text  NOT NULL,
    block_id bytea NOT NULL,
    PRIMARY KEY (token, block_id)
);
CREATE INDEX blind_block ON blind_index (block_id);

CREATE TABLE ie_scores (
    ie_id    text   NOT NULL,
    ms_index bigint NOT NULL,
    ts       bigint NOT NULL,
    score    double precision NOT NULL,
    block_id bytea  NOT NULL,
    verdict  text,
    PRIMARY KEY (ie_id, block_id)
);
CREATE INDEX ie_scores_ms ON ie_scores (ie_id, ms_index);

CREATE TABLE alerts (
    id       bigserial PRIMARY KEY,
    rule     text   NOT NULL,
    severity text   NOT NULL,
    block_id bytea,
    ie_id    text,
    evidence jsonb  NOT NULL DEFAULT '{}',
    ts       bigint NOT NULL
);
CREATE UNIQUE INDEX alerts_dedupe
    ON alerts (rule, coalesce(block_id, ''::bytea), coalesce(ie_id, ''));

CREATE TABLE anchors (
    ms_index bigint PRIMARY KEY,
    root     bytea,
    ref      text,
    ts       bigint,
    meta     jsonb NOT NULL DEFAULT '{}'
);

CREATE TABLE events (
    id      bigserial PRIMARY KEY,
    type    text   NOT NULL,
    payload jsonb  NOT NULL DEFAULT '{}',
    ts      bigint NOT NULL
);

CREATE TABLE cursor (
    id smallint PRIMARY KEY CHECK (id = 1),
    ms bigint NOT NULL
);

CREATE TABLE submissions (
    sub_id         text PRIMARY KEY,
    received_at_ms bigint NOT NULL,
    source         text   NOT NULL CHECK (source IN ('mqtt', 'http')),
    tag            text,
    message_json   jsonb,
    data_hex       text,
    block_id       bytea,
    hornet_status  integer,
    relay_verdict  text,
    iss            text,
    seq            bigint
);
CREATE UNIQUE INDEX submissions_block ON submissions (block_id) WHERE block_id IS NOT NULL;

CREATE TABLE validations (
    id                    bigserial PRIMARY KEY,
    block_id              bytea  NOT NULL,
    checked_at_ms         bigint NOT NULL,
    is_solid              boolean NOT NULL,
    referenced_by_ms      integer,
    ledger_inclusion_state text,
    should_reattach       boolean
);
CREATE INDEX validations_block ON validations (block_id, checked_at_ms);

CREATE TABLE content_checks (
    id            bigserial PRIMARY KEY,
    block_id      bytea  NOT NULL,
    checked_at_ms bigint NOT NULL,
    result        text   NOT NULL CHECK (result IN ('MATCH', 'MISMATCH', 'NOT_FOUND')),
    diff          jsonb
);
CREATE INDEX content_checks_block ON content_checks (block_id, checked_at_ms);

CREATE TABLE lifecycle (
    id       bigserial PRIMARY KEY,
    block_id bytea,
    sub_id   text,
    status   text   NOT NULL CHECK (status IN ('RECEIVED', 'SUBMITTED', 'SOLID', 'CONFIRMED',
        'CONTENT_VERIFIED', 'CONTENT_MISMATCH', 'NOT_FOUND', 'ORPHANED', 'SHADOW')),
    at_ms    bigint NOT NULL,
    detail   jsonb
);
CREATE INDEX lifecycle_block ON lifecycle (block_id, at_ms);
CREATE INDEX lifecycle_sub   ON lifecycle (sub_id);

CREATE TABLE incidents (
    id           bigserial PRIMARY KEY,
    opened_at_ms bigint NOT NULL,
    closed_at_ms bigint,
    ie_id        text,
    severity     text NOT NULL,
    title        text NOT NULL,
    status       text NOT NULL DEFAULT 'open'
);

CREATE TABLE incident_events (
    incident_id bigint NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    block_id    bytea  NOT NULL,
    role        text   NOT NULL,
    PRIMARY KEY (incident_id, block_id)
);
