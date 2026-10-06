#!/usr/bin/env bash
# Start a throwaway PostgreSQL for the test suite (port 55432).
set -euo pipefail
if docker ps --format '{{.Names}}' | grep -qx witness-testdb; then echo "witness-testdb already running"; exit 0; fi
docker rm -f witness-testdb >/dev/null 2>&1 || true
docker run -d --name witness-testdb -p 55432:5432 -e POSTGRES_PASSWORD=witness postgres:16-alpine >/dev/null
for i in $(seq 1 30); do docker exec witness-testdb pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
echo "export WITNESS_TEST_PG=postgresql://postgres:witness@localhost:55432/postgres"
