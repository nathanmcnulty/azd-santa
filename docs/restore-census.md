# Read-only restore census

`experiments/server/restore_census.py` is the next bounded layer toward issues
[54](https://github.com/nathanmcnulty/azd-santa/issues/54) and
[79](https://github.com/nathanmcnulty/azd-santa/issues/79). It observes an already
isolated database; it does not restore one, initialize Django, connect,
authenticate, start services, alter rows, rewrap secrets or establish authority.
It adds no dependencies and has no CLI, stdout, automatic files or replay path.
The authenticated archive and three-model rewrap APIs are unchanged.

The caller must provide an already-open PostgreSQL Django DatabaseWrapper
(`connections['default']`, rather than Django's connection proxy) in autocommit
mode, an initialized registry from reviewed source, a confidential 32-byte HMAC
key, limits, and externally enforced process/network isolation without current
operator or workload secrets. READ ONLY is not containment: untrusted functions,
casts, type output and imports can execute code or cause external effects. No implicit
connection or nested transaction is accepted. Do not initialize Django from
archived executable source: imports, AppConfig callbacks and migration imports
are executable behavior, not data. This primitive does not attest source/image,
Django/driver/version, connection provenance, caller authority or isolation.
Those remain separate prerequisites before any actual database invocation.

The raw driver must be psycopg2-binary2.9.11, the version declared in the pinned
Zentral requirements constraints, with an open psycopg2 connection, raw
autocommit enabled and positive `get_transaction_status()` IDLE evidence before
any cursor or BEGIN. ACTIVE, INTRANS (including raw BEGIN hidden from Django),
INERROR, UNKNOWN, missing APIs and other drivers/versions reject without SQL or
ROLLBACK. No IDLE state is synthesized from Django flags. This is an exclusively
owned dedicated connection: do not share it with other threads/callers. Driver
identity/version strings are compatibility checks, not provenance authentication.


`collect(connection, apps, fingerprint_key=key, limits=Limits())` opens one
`REPEATABLE READ READ ONLY` transaction, sets statement/lock/idle timeouts and
canonical output settings, and always rolls it back. It uses server cursors and
bounded fetches, checks complete scans, rejects excess rows/facts/bytes/deadlines,
and requests server-side value-size checks before returning row payloads.
Statement timeout bounds each SQL statement; an external process deadline still
must bound driver I/O, Python imports and all other blocking behavior. A failed
rollback/close returns a fixed error; discard that connection rather than retry.

The private manifest contains:

- The complete supplied Django registry, including baseline apps, proxy, swapped,
  unmanaged and auto-created through models, forward/reverse fields, concrete
  columns and relationship/through targets. The nine required configured labels
  are accounts, realms, compliance_checks, incidents, probes, stores, terraform,
  inventory and santa. This minimum check is not a complete installed-profile
  attestation; the full registry must match the independently reviewed baseline.
- Every disk migration hash, declared dependencies/replacements/run-before edges,
  effective graph parents and every applied database record. Unknown or duplicate
  applied nodes and inconsistent history reject. Migration records are first
  scanned under the same snapshot and limits before the real Django loader reads
  them. Migration modules and their dependencies are trusted executable source;
  local fake-loader tests do not qualify real Django behavior.
- Non-system namespaces, relations, columns/defaults/collations (including dropped
  column tombstones as catalog facts, without pretending to read dropped values), constraints,
  indexes, triggers, rules, row-security policies, types, routine definitions,
  sequence definitions, extensions and database/collation observations. Recursive
  dependency identities expose unsupported catalog classes. This is a supported
  schema census, not an implementation of every PostgreSQL object kind.
- A count and keyed canonical multiset fingerprint of every supported physical
  table, partition, materialized view and sequence, including empty relations and
  duplicate rows. `ONLY` prevents inheritance/partition double counting. Plain
  views retain definitions rather than execute their queries. Quoted relation
  keys distinguish names containing punctuation. Read DECLARE statements bind no
  parameters; only a strictly validated integer limit is embedded, so literal %
  characters inside quoted identifiers bypass driver pyformat parsing. Row values are not retained,
  except bounded migration metadata. Schema definitions can themselves contain
  secrets, so the entire manifest remains confidential.

No data scan occurs if preflight finds unsupported objects, foreign tables,
custom column types (including normal/user OIDs masquerading inside pg_catalog),
generated columns, RLS, unsupported routines/types, large
objects, foreign servers, publications/subscriptions, event triggers or custom
casts. The private observation retains blocker identities and reports
`complete_supported_data=false`; comparison rejects it. There is no fallback to
partial coverage. Other catalog classes remain explicit blockers until their
schema and execution semantics receive a reviewed adapter.

The collector follows recorded `pg_depend` references out of the inventoried
objects. References whose targets resolve to `pg_catalog`, other `pg_*`
namespaces, or `information_schema` become private `excluded_reference`
blockers. This stops collection before application row reads and prevents a
comparison even when the two names match. PostgreSQL's automatic dependency
from a generated TOAST index to its own heap is treated as internal storage.
Recollect older manifests with the updated collector since they lack this
catalog inventory.

Referenced definitions remain an explicit unproven gate. PostgreSQL omits
dependency edges to pinned objects and may omit dependencies inside routine
bodies. Namespace-less and external objects still require independent review.
Bind those definitions and relevant global objects against the reviewed
engine/source baseline before full restore acceptance. Observation and
comparison continue to report `referenced_definitions='unproven'` and
`schema_complete=false`. See the PostgreSQL documentation for
[catalog dependency records](https://www.postgresql.org/docs/18/catalog-pg-depend.html)
and [dependencies inside routines](https://www.postgresql.org/docs/18/ddl-depend.html).

Sequence values are not MVCC-consistent even inside repeatable-read. The receipt
always leaves `sequence_quiescence_proven=false`; independently proven stopped
writers are required before interpreting the sequence/data observations as a
consistent restore baseline. Cluster roles/grants, PostgreSQL engine integrity,
source/image retention, secret-engine provenance, Redis/broker work, media and
native Elasticsearch restoration remain separate gates.

`coverage_items()` provides private review keys for every app, model, field,
physical relation, migration fact and catalog fact. `compare(observed, expected, dispositions,
fingerprint_key=key)` requires the entire independently reviewed expected manifest
and the exact complete disposition map. It rejects additions, omissions, field,
relationship, migration, schema or row changes and incoherent model/table/column
coverage, including scalar primary/unique/foreign-key agreement. Models in this
known profile use public tables; unsupported schema-qualified model mappings
reject rather than guess. No default disposition exists. Dispositions describe intended later
handling; this function performs none. A copied baseline/map, shared HMAC key or
matching fingerprint cannot authenticate completeness/provenance/current
external authority. Counts and fingerprints deliberately keep all such claims
false; HMAC protects against public guessing only while its caller-held key and
private manifest remain confidential. Use the same retained key for comparison.

Offline tests use controlled SQL/registry/loader adapters to exercise transaction
order, rollback/redaction, exact coverage, changes, unsupported objects and
limits. The Linux check runs the exact excluded-reference query using the pinned
PostgreSQL 18 image with Docker networking disabled. It checks a plain table and
references to a synthetic routine, collation and operator class. The full
collector still needs qualification with the pinned database, real Django
registry and migration loader inside a non-listening disposable destination.
Full administrator/device reissue and application/native postflight remain open.
