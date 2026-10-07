-- The API's own database login, witness_api (created by deploy/compose/db-init.sql), reads the
-- explorer's schema and writes only what the API itself records: submissions and their
-- lifecycle (POST /ingest), node checks (POST /messages/{id}/verify: validations, content
-- checks, the alerts and service status they raise, events) and audit reports. It changes no
-- message but its status, deletes nothing and creates nothing; the indexer migrates.
-- Skipped where the role does not exist (tests, deployments that use one login). Idempotent:
-- deploy/compose/db-init.sql runs it again for a database migrated before this file.
DO $$
DECLARE
  t text;
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'witness_api') THEN
    RETURN;
  END IF;
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO witness_api', current_schema());
  EXECUTE format('GRANT SELECT ON ALL TABLES IN SCHEMA %I TO witness_api', current_schema());
  EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO witness_api',
                 current_schema());
  -- Tables a later migration adds are readable too.
  EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT ON TABLES TO witness_api',
                 current_schema());
  EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT USAGE, SELECT ON SEQUENCES '
                 'TO witness_api', current_schema());
  FOREACH t IN ARRAY ARRAY['submissions', 'lifecycle', 'validations', 'content_checks',
                           'alerts', 'events', 'service_status', 'reports'] LOOP
    IF to_regclass(t) IS NOT NULL THEN
      EXECUTE format('GRANT INSERT ON %I TO witness_api', t);
    END IF;
  END LOOP;
  FOREACH t IN ARRAY ARRAY['service_status', 'reports'] LOOP
    IF to_regclass(t) IS NOT NULL THEN
      EXECUTE format('GRANT UPDATE ON %I TO witness_api', t);
    END IF;
  END LOOP;
  IF to_regclass('messages') IS NOT NULL THEN
    GRANT UPDATE (status, confirmed_at_ms) ON messages TO witness_api;
  END IF;
END
$$;
