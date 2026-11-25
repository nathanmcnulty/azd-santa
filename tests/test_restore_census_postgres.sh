#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

image="$(python -c 'import json; print(json.load(open("experiments/server/dependency-images.lock.json"))["postgres"])')"
[[ "$image" =~ ^postgres@sha256:[0-9a-f]{64}$ ]]
container="$(docker run --detach --network none --memory 512m --cpus 1 --pids-limit 128 \
  --tmpfs /var/lib/postgresql:rw,size=256m --env POSTGRES_HOST_AUTH_METHOD=trust \
  "$image" -c listen_addresses=)"
trap 'docker rm -f "$container" >/dev/null' EXIT

# Wait for the actual postgres process, since initdb also starts a temporary
# socket-only postmaster while the entrypoint still owns PID 1.
ready=false
for ((attempt=0; attempt<30; attempt++)); do
  if [[ "$(docker exec "$container" cat /proc/1/comm)" == postgres ]] &&
     docker exec "$container" pg_isready --username postgres --quiet; then
    ready=true
    break
  fi
  sleep 1
done
[[ "$ready" == true ]]

{
  echo 'CREATE TABLE census_probe (value integer NOT NULL, notes text);'
  python - <<'PY'
import sys
sys.path.insert(0, 'experiments/server')
from restore_census import CATALOG

print('CREATE TEMP VIEW census_excluded_reference AS SELECT fact::jsonb AS fact FROM (')
print(CATALOG['excluded_references'])
print(') AS reference(fact);')
PY
  cat <<'SQL'
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM census_excluded_reference) THEN
    RAISE EXCEPTION 'Plain table unexpectedly blocked';
  END IF;
END $$;
CREATE FUNCTION pg_catalog.census_local_fn(integer) RETURNS integer
LANGUAGE sql IMMUTABLE AS 'SELECT $1';
ALTER TABLE census_probe ADD CHECK (pg_catalog.census_local_fn(value) > 0);
CREATE COLLATION pg_catalog.census_local_order FROM pg_catalog."C";
ALTER TABLE census_probe ADD COLUMN label text COLLATE pg_catalog.census_local_order;
CREATE OPERATOR CLASS pg_catalog.census_local_ops FOR TYPE integer USING btree AS
  OPERATOR 1 < (integer, integer), FUNCTION 1 btint4cmp(integer, integer);
CREATE INDEX census_probe_value ON census_probe (value pg_catalog.census_local_ops);
DO $$ DECLARE observed text[]; BEGIN
  SELECT array_agg(DISTINCT fact->>'catalog' ORDER BY fact->>'catalog')
    INTO observed FROM census_excluded_reference;
  IF observed IS DISTINCT FROM ARRAY['pg_collation','pg_opclass','pg_proc'] THEN
    RAISE EXCEPTION 'Unexpected blocker catalogs: %', observed;
  END IF;
  IF (SELECT current_setting('server_version_num')::integer / 10000) <> 18 THEN
    RAISE EXCEPTION 'Expected pinned PostgreSQL 18';
  END IF;
END $$;
SQL
} | docker exec -i "$container" psql --no-psqlrc --username postgres --set ON_ERROR_STOP=1
