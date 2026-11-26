"""Apply reviewed authority updates to one already isolated restore database."""

from dataclasses import asdict, dataclass
from datetime import timezone
import hmac
from pathlib import Path
import re
import time

import restore_authority_plan as authority
import restore_census as census

TABLES = {
    'accounts.user': ('accounts_user', 'id'),
    'accounts.policy': ('accounts_policy', 'id'),
    'accounts.apitoken': ('accounts_apitoken', 'id'),
    'accounts.oidcapitokenissuer': ('accounts_oidcapitokenissuer', 'id'),
    'sessions.session': ('django_session', 'session_key'),
    'realms.realm': ('realms_realm', 'uuid'),
    'realms.realmauthenticationsession': ('realms_realmauthenticationsession', 'uuid'),
    'inventory.enrollmentsecret': ('inventory_enrollmentsecret', 'id'),
}


class TransactionRejected(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    database: str
    role: str
    socket_dir: str
    database_oid: int
    system_identifier: int
    postmaster_started: str


def require(condition):
    if not condition:
        raise TransactionRejected('Restore authority transaction rejected')


def connection_ready(connection):
    require(connection.vendor == 'postgresql' and connection.connection is not None
            and connection.connection.closed == 0 and connection.get_autocommit() is True
            and connection.in_atomic_block is False
            and (connection.health_check_enabled is False or connection.health_check_done is True))
    census.require_idle(connection)


def binding(connection, cursor):
    host = connection.settings_dict['HOST']
    require(type(host) is str and Path(host).is_absolute() and str(Path(host).resolve(strict=True)) == host)
    cursor.execute("""SELECT pg_catalog.current_database(), current_user, session_user, pg_catalog.inet_server_addr(),
        d.oid::bigint, c.system_identifier, pg_catalog.pg_postmaster_start_time() AT TIME ZONE 'UTC',
        pg_catalog.pg_backend_pid(), pg_catalog.pg_is_in_recovery(), pg_catalog.current_setting('server_version_num')
        FROM pg_catalog.pg_database d CROSS JOIN pg_catalog.pg_control_system() c
        WHERE d.datname=pg_catalog.current_database()""")
    database, role, session, address, oid, cluster, started, pid, recovery, version = cursor.fetchone()
    require(re.fullmatch(r'azd_recovery_[a-f0-9]{24}', database) and role == session and address is None
            and database == connection.settings_dict['NAME'] and role == connection.settings_dict['USER']
            and recovery is False and int(version) // 10000 == 18)
    return Target(database, role, host, oid, cluster, started.isoformat()), pid


def read_target(connection):
    """Read the nonsecret database identity for independent target selection."""
    connection_ready(connection)
    with connection.cursor() as cursor:
        return binding(connection, cursor)[0]


def checked_tables(expected, *, tables=TABLES, exact_columns=None):
    catalog = expected.manifest['catalog']
    counts = {}
    for model, (table, primary_key) in tables.items():
        relations = [relation for relation in catalog['relations']
                     if (relation['schema'], relation['name']) == ('public', table)]
        require(len(relations) == 1 and relations[0]['kind'] == 'r'
                and not relations[0]['parents'] and not relations[0]['partition']
                and not relations[0]['row_security'])
        require(not any(item['schema'] == 'public' and item['table'] == table
                        for item in catalog['rules']))
        require(not any(item['schema'] == 'public' and item['table'] == table and not item['internal']
                        for item in catalog['triggers']))
        matches = [entry for entry in expected.manifest['registry']['models'] if entry['label'] == model]
        require(len(matches) == 1 and matches[0]['table'] == table
                and not matches[0]['proxy'] and not matches[0]['swapped'] and matches[0]['managed'])
        fields = {field['column'] for field in matches[0]['fields']
                  if field['local'] and field['concrete'] and field['column'] is not None}
        if exact_columns is None:
            require(fields >= (authority.PROJECTIONS[model][1].keys() | {primary_key}))
        else:
            physical = {column['name'] for column in catalog['columns']
                        if column['schema'] == 'public' and column['table'] == table
                        and not column['dropped']}
            require(fields == physical == exact_columns[model])
        require(any(item['schema'] == 'public' and item['table'] == table
                    and item['type'] == 'p' and item['columns'] == [primary_key]
                    for item in catalog['constraints']))
        counts[model] = expected.manifest['data'][census.relation_key('public', table)]['rows']
    return counts


def only_clients(cursor, target, writer_pid, observer_pid):
    cursor.execute('SELECT pg_catalog.pg_stat_clear_snapshot()')
    cursor.execute("""SELECT pid FROM pg_catalog.pg_stat_activity WHERE datid=%s
                      AND backend_type='client backend'""", (target.database_oid,))
    require({row[0] for row in cursor.fetchall()} == {writer_pid, observer_pid})


def projections(cursor, counts, deadline):
    result = {}
    for model, (table, primary_key) in TABLES.items():
        require(time.monotonic() < deadline)
        rules = authority.PROJECTIONS[model][1]
        columns = ', '.join(map(census.quote, (primary_key, *rules)))
        qualified = census.relation_key('public', table)
        cursor.execute(f'SELECT {columns} FROM ONLY {qualified} ORDER BY {census.quote(primary_key)} LIMIT %s',
                       (counts[model] + 1,))
        rows = []
        for primary, *values in cursor.fetchall():
            row = dict(zip(rules, values, strict=True), pk=primary)
            # The pinned Zentral settings use naive UTC. PostgreSQL's local
            # TimeZone was fixed to UTC before reading these columns.
            for field, rule in rules.items():
                if rule.startswith(('expire', 'revoke')) and row[field] is not None and row[field].tzinfo is None:
                    row[field] = row[field].replace(tzinfo=timezone.utc)
            rows.append(row)
        result[model] = rows
    return result


def run(writer, observer, registry, *, target, expected, dispositions, cutoff, fingerprint_key,
        limits=census.Limits(), apply=False, plan_digest=None):
    """Preview under locks or apply an explicitly pinned plan.

    Caller supplies two local already-open connections, a separately reviewed
    census and exclusive control of the restored database, with all application
    and maintenance writers stopped. This never opens listeners or reissues
    authority. An uncertain commit must be inspected without automatic replay.
    """
    cursor = None
    begun = committing = False
    try:
        require(type(target) is Target and type(limits) is census.Limits and type(apply) is bool
                and type(fingerprint_key) is bytes and len(fingerprint_key) == 32)
        require((not apply and plan_digest is None)
                or (apply and type(plan_digest) is str and re.fullmatch(r'[a-f0-9]{64}', plan_digest)))
        require(writer is not observer)
        connection_ready(writer)
        connection_ready(observer)
        require(writer.connection is not observer.connection)
        with observer.cursor() as read_cursor:
            observed_target, observer_pid = binding(observer, read_cursor)
        require(observed_target == target)
        counts = checked_tables(expected)
        require(all(type(count) is int and count >= 0 for count in counts.values())
                and sum(counts.values()) <= limits.rows)
        deadline = time.monotonic() + limits.seconds
        cursor = writer.cursor()
        begun = True
        cursor.execute('BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE')
        for option, value in (('statement_timeout', str(limits.statement_ms)), ('lock_timeout', str(limits.lock_ms)),
                              ('idle_in_transaction_session_timeout', str(limits.seconds*1000)),
                              ('TimeZone', 'UTC'), ('search_path', 'pg_catalog'), ('row_security', 'off')):
            cursor.execute('SELECT pg_catalog.set_config(%s,%s,true)', (option, value))
        actual_target, writer_pid = binding(writer, cursor)
        require(actual_target == target and writer_pid != observer_pid)
        only_clients(cursor, target, writer_pid, observer_pid)
        locked = ', '.join('ONLY ' + census.relation_key('public', table) for table, _ in sorted(TABLES.values()))
        cursor.execute(f'LOCK TABLE {locked} IN SHARE ROW EXCLUSIVE MODE NOWAIT')
        observed = census.collect(observer, registry, fingerprint_key=fingerprint_key, limits=limits)
        comparison = census.compare(observed, expected, dispositions, fingerprint_key=fingerprint_key)
        rows = projections(cursor, counts, deadline)
        projection = authority.plan(rows, counts, cutoff=cutoff, fingerprint_key=fingerprint_key, limits=limits)
        cursor.execute('SELECT pg_catalog.clock_timestamp() AT TIME ZONE \'UTC\'')
        require(cutoff.astimezone(timezone.utc).replace(tzinfo=None) <= cursor.fetchone()[0])
        digest = census.keyed(fingerprint_key, 'authority-transaction-plan',
                              {'target': asdict(target), 'census': comparison['fingerprint'],
                               'projection': projection.receipt})
        receipt = {**projection.receipt, 'scope': 'restore-authority-transaction-v1',
                   'plan_digest': digest, 'authority_updates_committed': False}
        if not apply:
            return receipt
        require(hmac.compare_digest(digest, plan_digest))
        updated = 0
        for model, changes in projection.updates.items():
            table, primary_key = TABLES[model]
            qualified = census.relation_key('public', table)
            original = {row['pk']: row for row in rows[model]}
            for change in changes:
                require(time.monotonic() < deadline)
                fields = change['fields']
                assignments = ', '.join(census.quote(name) + '=%s' for name in fields)
                cursor.execute(f'UPDATE ONLY {qualified} SET {assignments} WHERE {census.quote(primary_key)}=%s',
                               (*fields.values(), change['pk']))
                require(cursor.rowcount == 1)
                original[change['pk']].update(fields)
                updated += 1
        require(projections(cursor, counts, deadline) == rows)
        only_clients(cursor, target, writer_pid, observer_pid)
        require(time.monotonic() < deadline)
        committing = True
        cursor.execute('COMMIT')
        begun = False
        return {**receipt, 'performs_mutation': bool(updated), 'authority_updates_committed': True}
    except Exception:
        if committing:
            raise TransactionRejected('Restore authority commit unverified; discard the connection and inspect') from None
        raise TransactionRejected('Restore authority transaction rejected; retain the original inputs') from None
    finally:
        if cursor is not None:
            try:
                try:
                    if begun and not committing:
                        cursor.execute('ROLLBACK')
                finally:
                    cursor.close()
            except Exception:
                raise TransactionRejected('Restore authority cleanup unverified; discard the connection and inspect') from None
