"""Transactional secret rewrap for one already-isolated Zentral recovery database."""
from dataclasses import asdict
from datetime import datetime
import hmac
import json
import re
import time
from uuid import UUID

import restore_authority_transaction as recovery
import restore_census as census
import secret_rewrap as secret

TABLES = {
    'stores.store': ('stores_store', 'id'),
    'probes.action': ('probes_action', 'id'),
    'terraform.stateversion': ('terraform_stateversion', 'id'),
}
COLUMNS = dict(zip(TABLES, (secret.STORE_FIELDS, secret.ACTION_FIELDS, secret.STATE_FIELDS), strict=True))


class TransactionRejected(ValueError):
    """Fixed messages exclude the secret material and SQL values."""


def require(ok):
    if not ok:
        raise TransactionRejected('Restore secret transaction rejected')


def field_value(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, memoryview):
        return bytes(value)
    return value


def project(cursor, counts, deadline):
    results = {}
    budget = [0, 0]
    for model, (name, primary) in TABLES.items():
        require(time.monotonic() < deadline)
        ordered = sorted(COLUMNS[model])
        selected = ', '.join(census.quote(column) + ('::text' if column == 'backend_kwargs' else '')
                             for column in ordered)
        table = census.relation_key('public', name)
        cursor.execute(f'SELECT {selected} FROM ONLY {table} ORDER BY {census.quote(primary)} LIMIT %s',
                       (counts[model] + 1,))
        rows = []
        for values in cursor:
            require(time.monotonic() < deadline)
            row = dict(zip(ordered, map(field_value, values), strict=True))
            if 'backend_kwargs' in row:
                raw = row['backend_kwargs']
                require(type(raw) is str and len(raw.encode()) <= secret.MAX_BYTES)
                row['backend_kwargs'] = json.loads(raw, object_pairs_hook=census.unique)
            secret.bounded(row, budget)
            rows.append(row)
        require(len(rows) == counts[model])
        results[model] = rows
    return results


def apply_fields(cursor, before, replacement, contexts, deadline):
    originals = {model: {row['id']: row for row in rows} for model, rows in before.items()}
    outputs = {model: {row['id']: row for row in rows} for model, rows in replacement.items()}
    count = 0
    for context in contexts:
        require(time.monotonic() < deadline)
        model, identifier, path = context['model'], context['pk'], context['field'].split('.')
        old, new = originals[model][identifier], outputs[model][identifier]
        table, primary = TABLES[model]
        qualified = census.relation_key('public', table)
        primary = census.quote(primary)
        if model == 'terraform.stateversion':
            require(path == ['encryption_key'])
            if new['encryption_key'] == old['encryption_key']:
                continue
            cursor.execute(f'UPDATE ONLY {qualified} SET encryption_key=%s '
                           f'WHERE {primary}=%s AND encryption_key=%s',
                           (new['encryption_key'], identifier, old['encryption_key']))
        else:
            old_token, new_token = old['backend_kwargs'], new['backend_kwargs']
            for part in path:
                index = int(part) if isinstance(old_token, list) else part
                old_token, new_token = old_token[index], new_token[index]
            if old_token == new_token:
                continue
            # Only replace the verified leaf. Serializing the entire JSONB
            # document would round unrelated PostgreSQL numeric values.
            cursor.execute(f'UPDATE ONLY {qualified} '
                           f'SET backend_kwargs=pg_catalog.jsonb_set(backend_kwargs,%s::text[],'
                           f'pg_catalog.to_jsonb(%s::text),false) '
                           f'WHERE {primary}=%s AND (backend_kwargs #>> %s::text[]) = %s',
                           (path, new_token, identifier, path, old_token))
        require(cursor.rowcount == 1)
        count += 1
    return count


def material_binding(material):
    return {name: {**asdict(item), 'passwords': list(item.passwords)} for name, item in material.items()}


def run(writer, observer, registry, *, target, expected, dispositions, expected_contexts,
        old_material, new_material, targets, fingerprint_key, limits=census.Limits(),
        apply=False, plan_digest=None):
    """Preview and apply an explicitly pinned rewrap to an isolated copy.

    Caller supplies independently reviewed coverage and contexts, verified engine
    material, two exclusive open local connections and an outer deadline. All
    other clients and writers must remain stopped. A commit failure is an unknown
    outcome and requires inspection before any recovery action.
    """
    cursor = None
    begun = committing = False
    try:
        require(type(target) is recovery.Target and type(limits) is census.Limits and type(apply) is bool
                and type(fingerprint_key) is bytes and len(fingerprint_key) == 32)
        require((not apply and plan_digest is None)
                or (apply and type(plan_digest) is str and re.fullmatch(r'[a-f0-9]{64}', plan_digest)))
        require(writer is not observer)
        recovery.connection_ready(writer)
        recovery.connection_ready(observer)
        require(writer.connection is not observer.connection)
        with observer.cursor() as observed:
            observed_target, observer_pid = recovery.binding(observer, observed)
        require(observed_target == target)
        counts = recovery.checked_tables(expected, tables=TABLES, exact_columns=COLUMNS)
        require(all(type(count) is int and count >= 0 for count in counts.values())
                and sum(counts.values()) <= min(secret.MAX_ROWS, limits.rows))
        deadline = time.monotonic() + limits.seconds
        cursor = writer.cursor()
        begun = True
        cursor.execute('BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE')
        for option, value in (('statement_timeout', str(limits.statement_ms)), ('lock_timeout', str(limits.lock_ms)),
                              ('idle_in_transaction_session_timeout', str(limits.seconds * 1000)),
                              ('TimeZone', 'UTC'), ('search_path', 'pg_catalog'), ('row_security', 'off')):
            cursor.execute('SELECT pg_catalog.set_config(%s,%s,true)', (option, value))
        actual_target, writer_pid = recovery.binding(writer, cursor)
        require(actual_target == target and writer_pid != observer_pid)
        recovery.only_clients(cursor, writer_pid, observer_pid)
        locked = ', '.join('ONLY ' + census.relation_key('public', name) for name, _ in sorted(TABLES.values()))
        cursor.execute(f'LOCK TABLE {locked} IN SHARE ROW EXCLUSIVE MODE NOWAIT')
        observed = census.collect(observer, registry, fingerprint_key=fingerprint_key, limits=limits)
        comparison = census.compare(observed, expected, dispositions, fingerprint_key=fingerprint_key)
        rows = project(cursor, counts, deadline)
        result = secret.rewrap_projection(apps=secret.APPS, stores=rows['stores.store'],
            actions=rows['probes.action'], state_versions=rows['terraform.stateversion'],
            expected_contexts=expected_contexts, old_material=old_material, new_material=new_material, targets=targets)
        # Replacement ciphertext is intentionally randomized. Bind the plan to
        # the original census, exact target, selected contexts and both sets of
        # material without including raw passwords or projected values in receipts.
        digest = census.keyed(fingerprint_key, 'secret-rewrap-transaction-plan', {
            'target': asdict(target), 'census': comparison['fingerprint'], 'contexts': expected_contexts,
            'targets': targets, 'counts': result.receipt,
            'old': material_binding(old_material), 'new': material_binding(new_material)})
        receipt = {**result.receipt, 'scope': 'restore-secret-transaction-v1', 'plan_digest': digest,
                   'rewrap_committed': False, 'performs_mutation': False}
        if not apply:
            return receipt
        require(hmac.compare_digest(digest, plan_digest))
        replacement = dict(zip(TABLES, (result.stores, result.actions, result.state_versions), strict=True))
        count = apply_fields(cursor, rows, replacement, expected_contexts, deadline)
        require(count == result.receipt['rewrapped'] and project(cursor, counts, deadline) == replacement)
        recovery.only_clients(cursor, writer_pid, observer_pid)
        require(time.monotonic() < deadline)
        committing = True
        cursor.execute('COMMIT')
        begun = False
        return {**receipt, 'performs_mutation': bool(count), 'rewrap_committed': True}
    except Exception:
        if committing:
            raise TransactionRejected('Restore secret commit unverified; discard the connection and inspect') from None
        raise TransactionRejected('Restore secret transaction rejected; retain the original inputs') from None
    finally:
        if cursor is not None:
            try:
                try:
                    if begun and not committing:
                        cursor.execute('ROLLBACK')
                finally:
                    cursor.close()
            except Exception:
                raise TransactionRejected('Restore secret cleanup unverified; discard the connection and inspect') from None
