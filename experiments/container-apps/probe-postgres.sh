set -euo pipefail

# Refuse to write if the platform supplied a different filesystem or mount.
if ! awk '$2 == "/mnt/probe" && $3 == "nfs4" {
    count = split($4, options, ",")
    for (i = 1; i <= count; i++) {
        if (options[i] == "hard") hard = 1
        if (options[i] == "vers=4.1") v41 = 1
    }
    ok = hard && v41
}
END { exit !ok }' /proc/mounts; then
    echo 'Expected a hard NFSv4.1 mount at /mnt/probe.' >&2
    exit 1
fi

data_dir=$(mktemp -d /mnt/probe/pg.XXXXXXXX)
socket_dir=$(mktemp -d)
trap 'gosu postgres pg_ctl -D "$data_dir" -m fast -w stop >/dev/null 2>&1 || true; rm -rf -- "$data_dir" "$socket_dir"' EXIT
chown postgres:postgres "$data_dir" "$socket_dir"

gosu postgres initdb -D "$data_dir" --auth-local=peer --auth-host=reject --no-locale
server_options="-c listen_addresses= -c unix_socket_directories=$socket_dir"
gosu postgres pg_ctl -D "$data_dir" -o "$server_options" -w start
gosu postgres psql -X -h "$socket_dir" -d postgres -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE mount_probe (value integer PRIMARY KEY);
INSERT INTO mount_probe VALUES (42);
SQL
gosu postgres pg_ctl -D "$data_dir" -m fast -w stop
gosu postgres pg_ctl -D "$data_dir" -o "$server_options" -w start

value=$(gosu postgres psql -X -h "$socket_dir" -d postgres -v ON_ERROR_STOP=1 -Atc 'SELECT value FROM mount_probe')
test "$value" = 42
gosu postgres pg_ctl -D "$data_dir" -m fast -w stop
echo 'PostgreSQL committed data survived a restart on a hard NFSv4.1 mount.'
