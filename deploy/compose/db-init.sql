-- Database roles of the Witness overlay, run by the witness-db-init service (psql, as the
-- database owner) before the relay starts. Idempotent: safe on a new and on an existing database.
--
-- witness_relay: the relay's own login. It owns the relay schema (receipts, issuer sequence
-- numbers) and nothing else: no CREATE on the database, no access to the explorer's schema.
-- Its password comes from RELAY_DB_PASSWORD (secrets/postgres/relay.password).
\set ON_ERROR_STOP on
\getenv relay_password RELAY_DB_PASSWORD

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
