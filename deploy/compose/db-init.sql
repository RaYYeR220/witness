-- Database roles of the Witness overlay, run by the witness-db-init service (psql, as the
-- database owner) before the relay starts. Idempotent: safe on a new and on an existing database.
--
-- witness_relay: the relay's own login. It owns the relay schema (receipts, issuer sequence
-- numbers) and nothing else: no CREATE on the database, no access to the explorer's schema.
-- Its password comes from RELAY_DB_PASSWORD (secrets/postgres/relay.password).
--
-- witness_api: the API's own login. It reads the explorer's schema (witness) and writes only
-- what the API records (indexer migration 0005_api_role.sql has the list); the indexer owns
-- the schema and migrates it. Its password comes from API_DB_PASSWORD
-- (secrets/postgres/api.password); without one the API keeps the owner's login.
\set ON_ERROR_STOP on
\getenv relay_password RELAY_DB_PASSWORD
\getenv api_password API_DB_PASSWORD

SELECT 'CREATE ROLE witness_relay'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'witness_relay') \gexec

SELECT format('ALTER ROLE witness_relay WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
              'NOREPLICATION NOBYPASSRLS PASSWORD %L', :'relay_password') \gexec

CREATE SCHEMA IF NOT EXISTS relay AUTHORIZATION witness_relay;
ALTER SCHEMA relay OWNER TO witness_relay;

-- Tables an earlier relay created under another role (indexes follow their table).
DO $$
DECLARE
  obj record;
BEGIN
  FOR obj IN
    SELECT c.oid::regclass AS name,
           CASE c.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW'
                          WHEN 'S' THEN 'SEQUENCE' ELSE 'TABLE' END AS kind
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'relay'
      AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
      AND c.relowner <> 'witness_relay'::regrole
      -- sequences owned by a column move with their table
      AND NOT (c.relkind = 'S' AND EXISTS (
        SELECT FROM pg_depend d
        WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype IN ('a', 'i')))
  LOOP
    EXECUTE format('ALTER %s %s OWNER TO witness_relay', obj.kind, obj.name);
  END LOOP;
END
$$;

\if :{?api_password}
SELECT 'CREATE ROLE witness_api'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'witness_api') \gexec

SELECT format('ALTER ROLE witness_api WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
              'NOREPLICATION NOBYPASSRLS PASSWORD %L', :'api_password') \gexec

-- The explorer's schema, owned by the database owner (the indexer's login), so the API can be
-- granted it before the indexer first migrates. Tables the indexer creates later are granted
-- by its migration 0005; on a database migrated before that, the same grants run here.
CREATE SCHEMA IF NOT EXISTS witness;
SET search_path TO witness;
-- Relative to this file, in the repository and in the witness-db-init container alike.
\ir ../../indexer/src/witness_indexer/migrations/0005_api_role.sql
RESET search_path;
\endif
