#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

image="$(python -c 'import json; print(json.load(open("experiments/server/dependency-images.lock.json"))["postgres"])')"
[[ "$image" =~ ^postgres@sha256:[0-9a-f]{64}$ ]]
elastic_image="$(python -c 'import json; print(json.load(open("experiments/server/dependency-images.lock.json"))["elasticsearch"])')"
[[ "$elastic_image" =~ ^docker\.elastic\.co/elasticsearch/elasticsearch@sha256:[0-9a-f]{64}$ ]]
docker pull "$elastic_image"
redis_image="$(python -c 'import json; print(json.load(open("experiments/server/dependency-images.lock.json"))["redis"])')"
[[ "$redis_image" =~ ^redis@sha256:[0-9a-f]{64}$ ]]
docker pull "$redis_image"
rabbit_image="$(python -c 'import json; print(json.load(open("experiments/server/dependency-images.lock.json"))["rabbitmq"])')"
[[ "$rabbit_image" =~ ^rabbitmq@sha256:[0-9a-f]{64}$ ]]
docker pull "$rabbit_image"
fixture_root="$(mktemp -d "$HOME/.santa-census.XXXXXXXX")"
container=''
restored_container=''
source_volume=''
restored_volume=''
copy_name="santa-census-${fixture_root##*/}-copy"
cleanup() {
  docker rm -f "$copy_name" >/dev/null 2>&1 || true
  docker rm -f -v "ci${fixture_root##*/}-elastic-source" "ci${fixture_root##*/}-elastic-restored" >/dev/null 2>&1 || true
  docker rm -f -v "ci${fixture_root##*/}-redis-source" "ci${fixture_root##*/}-redis-fresh" \
    "ci${fixture_root##*/}-redis-check" >/dev/null 2>&1 || true
  docker rm -f -v "ci${fixture_root##*/}-rabbit-source" "ci${fixture_root##*/}-rabbit-fresh" >/dev/null 2>&1 || true
  if [[ -n "$restored_container" ]]; then docker rm -f "$restored_container" >/dev/null; fi
  if [[ -n "$container" ]]; then docker rm -f "$container" >/dev/null; fi
  if [[ -n "$restored_volume" ]]; then docker volume rm "$restored_volume" >/dev/null; fi
  if [[ -n "$source_volume" ]]; then docker volume rm "$source_volume" >/dev/null; fi
  rm -rf -- "$fixture_root"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -m 1777 "$fixture_root/socket"
python -m venv "$fixture_root/venv"
fixture_python="$fixture_root/venv/bin/python"
"$fixture_python" -m pip install --only-binary=:all: \
  Django==5.2.18 psycopg2-binary==2.9.11 asgiref==3.8.1 sqlparse==0.6.0 cryptography==50.0.0
start_database() {
  local volume="$1"
  local listen_addresses="${SANTA_CENSUS_LISTEN_ADDRESSES:-}"
  shift
  docker run --detach --network none --memory 512m --cpus 1 --pids-limit 128 \
    --env PGDATA=/var/lib/postgresql/fixture \
    --mount "type=volume,source=$volume,target=/var/lib/postgresql,volume-nocopy" \
    --mount "type=bind,source=$fixture_root/socket,target=/fixture-socket" \
    "$@" "$image" -c "listen_addresses=$listen_addresses" -c unix_socket_directories=/var/run/postgresql,/fixture-socket
}

# Wait for the actual postgres process, since initdb also starts a temporary
# socket-only postmaster while the entrypoint still owns PID 1.
wait_database() {
  local id="$1"
  for ((attempt=0; attempt<30; attempt++)); do
    if [[ "$(docker exec "$id" cat /proc/1/comm)" == postgres ]] &&
       docker exec "$id" pg_isready --host /fixture-socket --username postgres --quiet; then
      return
    fi
    sleep 1
  done
  return 1
}

source_volume="$(docker volume create)"
restored_volume="$(docker volume create)"
[[ "$source_volume" =~ ^[a-f0-9]{64}$ && "$restored_volume" =~ ^[a-f0-9]{64}$ &&
   "$source_volume" != "$restored_volume" ]]
container="$(start_database "$source_volume" --env POSTGRES_HOST_AUTH_METHOD=trust --env POSTGRES_DB=santa_census_fixture)"
wait_database "$container"

{
  echo 'CREATE TABLE census_probe (value integer NOT NULL, notes text);'
  python - <<'PY'
import sys
sys.path.insert(0, 'experiments/server')
from restore_census import CATALOG

print('CREATE TEMP VIEW census_unreviewed_reference AS SELECT fact::jsonb AS fact FROM (')
print(CATALOG['unreviewed_references'])
print(') AS reference(fact);')
PY
  cat <<'SQL'
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM census_unreviewed_reference) THEN
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
    INTO observed FROM census_unreviewed_reference;
  IF observed IS DISTINCT FROM ARRAY['pg_collation','pg_opclass','pg_proc'] THEN
    RAISE EXCEPTION 'Unexpected blocker catalogs: %', observed;
  END IF;
  IF (SELECT current_setting('server_version_num')::integer / 10000) <> 18 THEN
    RAISE EXCEPTION 'Expected pinned PostgreSQL 18';
  END IF;
END $$;
DROP TABLE census_probe;
DROP OPERATOR CLASS pg_catalog.census_local_ops USING btree;
DROP OPERATOR FAMILY IF EXISTS pg_catalog.census_local_ops USING btree;
DROP COLLATION pg_catalog.census_local_order;
DROP FUNCTION pg_catalog.census_local_fn(integer);
SQL
} | docker exec -i "$container" psql --no-psqlrc --host /fixture-socket --username postgres --set ON_ERROR_STOP=1

env -i HOME="$fixture_root" PATH="$PATH" LC_ALL=C.UTF-8 \
  "$fixture_python" tests/run_restore_census_django.py "$fixture_root"

docker stop --timeout 15 "$container" >/dev/null
[[ "$(docker inspect --format '{{.State.Status}} {{.State.ExitCode}}' "$container")" == 'exited 0' ]]
[[ ! -e "$fixture_root/socket/.s.PGSQL.5432" ]]
docker run --rm --name "$copy_name" --network none --read-only --memory 256m --cpus 1 --pids-limit 32 \
  --env LC_ALL=C \
  --mount "type=volume,source=$source_volume,target=/capture,readonly,volume-nocopy" \
  --entrypoint /bin/bash "$image" -euo pipefail -c '
    test ! -e /capture/fixture/postmaster.pid
    pg_controldata /capture/fixture | grep -Ex "Database cluster state:[[:space:]]+shut down" >/dev/null
    size="$(du -sm --apparent-size /capture)"
    test "${size%%[[:space:]]*}" -le 192
    tar --format=pax --numeric-owner -C /capture -cpf - fixture
  ' | env -i HOME="$fixture_root" PATH="$PATH" LC_ALL=C.UTF-8 \
    "$fixture_python" tests/seal_restore_census_fixture.py "$fixture_root"

docker run --rm --name "$copy_name" --network none --read-only --memory 256m --cpus 1 --pids-limit 32 \
  --mount "type=bind,source=$fixture_root/quarantine/contents/volumes/postgres_data,target=/quarantined,readonly" \
  --mount "type=volume,source=$restored_volume,target=/restored,volume-nocopy" \
  --entrypoint /bin/bash "$image" -euo pipefail -c '
    test -z "$(ls -A /restored)"
    install -d -m 0700 /restored/fixture
    cp -R --no-preserve=ownership /quarantined/. /restored/fixture/
    chown -R postgres:postgres /restored/fixture
  '

# Start postgres directly. A missing or incomplete restored directory fails
# rather than allowing the image entrypoint to initialize a replacement.
restored_container="$(start_database "$restored_volume" --user postgres --entrypoint postgres)"
wait_database "$restored_container"
docker exec "$restored_container" psql --no-psqlrc --host /fixture-socket --username postgres \
  --dbname postgres --set ON_ERROR_STOP=1 \
  --command 'ALTER DATABASE santa_census_fixture RENAME TO azd_recovery_cccccccccccccccccccccccc'
env -i HOME="$fixture_root" PATH="$PATH" LC_ALL=C.UTF-8 \
  "$fixture_python" tests/run_restore_census_django.py "$fixture_root" --verify-restored

docker exec "$restored_container" createdb --host /fixture-socket --username postgres \
  azd_recovery_aaaaaaaaaaaaaaaaaaaaaaaa
env -i HOME="$fixture_root" PATH="$PATH" LC_ALL=C.UTF-8 \
  "$fixture_python" tests/run_restore_authority_transaction.py "$fixture_root"

docker exec "$restored_container" createdb --host /fixture-socket --username postgres \
  azd_recovery_bbbbbbbbbbbbbbbbbbbbbbbb
env -i HOME="$fixture_root" PATH="$PATH" LC_ALL=C.UTF-8 \
  "$fixture_python" tests/run_restore_secret_transaction.py "$fixture_root"

# Connecting over a Unix socket alone is insufficient. A dedicated copy
# must reject a postmaster that also listens on TCP, even on loopback.
docker stop --timeout 15 "$restored_container" >/dev/null
[[ "$(docker inspect --format '{{.State.Status}} {{.State.ExitCode}}' "$restored_container")" == 'exited 0' ]]
docker rm "$restored_container" >/dev/null
restored_container="$(SANTA_CENSUS_LISTEN_ADDRESSES=localhost start_database "$restored_volume" --user postgres --entrypoint postgres)"
wait_database "$restored_container"
env -i HOME="$fixture_root" PATH="$PATH" LC_ALL=C.UTF-8 \
  "$fixture_python" - "$fixture_root/socket" <<'PY'
from pathlib import Path
import sys

import django
from django.conf import settings
from django.db import connections

sys.path.insert(0, str(Path('experiments/server').resolve()))
from restore_authority_transaction import TransactionRejected, read_target

settings.configure(DATABASES={'default': dict(ENGINE='django.db.backends.postgresql',
    NAME='azd_recovery_aaaaaaaaaaaaaaaaaaaaaaaa', HOST=sys.argv[1], USER='postgres')})
django.setup()
connection = connections['default']
try:
    connection.ensure_connection()
    with connection.cursor() as cursor:
        cursor.execute("SELECT inet_server_addr(), current_setting('listen_addresses')")
        assert cursor.fetchone() == (None, 'localhost')
    try:
        read_target(connection)
    except TransactionRejected:
        print('Restore target rejected a TCP-enabled postmaster reached through a Unix socket')
    else:
        raise AssertionError('Restore target accepted a TCP-enabled postmaster')
finally:
    connection.close()
PY
