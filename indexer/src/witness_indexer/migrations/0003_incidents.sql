-- Incident Explorer: the correlation state each incident carries.
--   keys           what the incident is about: 'ie:<IE id>', 'sc:<service component>', 'ledger'
--   last_event_ms  time of its latest event (correlation window, quiet close)
--   baseline_*     the IE's last proven trust score before the incident, then the one its
--                  first trust drop fell from (the recovery target)
--   low_score      the lowest trusted score since its first trust drop (none: no drop yet)
--   closed_by      the block that closed it (a recovered trust score)
ALTER TABLE incidents
    ADD COLUMN keys              text[] NOT NULL DEFAULT '{}',
    ADD COLUMN last_event_ms     bigint,
    ADD COLUMN baseline_score    double precision,
    ADD COLUMN baseline_block_id bytea,
    ADD COLUMN low_score         double precision,
    ADD COLUMN closed_by         bytea,
    ADD COLUMN updated_at_ms     bigint;

CREATE INDEX incidents_open_keys ON incidents USING gin (keys) WHERE status = 'open';
CREATE INDEX incidents_status ON incidents (status, last_event_ms);

-- When the event happened (message time, not attach time) and what the engine saw in it.
ALTER TABLE incident_events
    ADD COLUMN at_ms  bigint,
    ADD COLUMN detail jsonb;

CREATE INDEX incident_events_block ON incident_events (block_id);

-- Alerts that joined an incident, including the ones that name no block (ANCHOR_MISMATCH).
-- An alert joins at most one incident.
CREATE TABLE incident_alerts (
    alert_id       bigint PRIMARY KEY REFERENCES alerts (id) ON DELETE CASCADE,
    incident_id    bigint NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
    attached_at_ms bigint NOT NULL
);

CREATE INDEX incident_alerts_incident ON incident_alerts (incident_id);

-- The engine looks up the alerts raised on a block as it correlates the block.
CREATE INDEX alerts_block ON alerts (block_id);
