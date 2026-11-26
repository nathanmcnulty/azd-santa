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
- Database-wide and schema-specific default privileges are recorded with their
  owner, object type, named grantor and grantee, privilege, and grant option.
  Database-wide scope and grants to PUBLIC have explicit null fields. The
  comparator checks these settings even when existing object ACLs and rows
  match. This covers the initial privileges PostgreSQL assigns when new
  objects are created. See [the PostgreSQL default privilege catalog](https://www.postgresql.org/docs/18/catalog-pg-default-acl.html).
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
objects. References into `pg_catalog`, other `pg_*` namespaces,
`information_schema`, and database-local objects that have no namespace and
fall outside the census become private `unreviewed_reference` blockers.
A custom table access method is one example. Unresolved identities also stop
collection. The extension catalog supplies the existing extension observations.
PostgreSQL's automatic dependency from a generated TOAST index to its own heap
is treated as internal storage. These checks run before application row reads
and prevent comparison even when two object names match. Recollect older
manifests because they lack the updated catalog inventory.

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
limits. The Linux check uses the pinned PostgreSQL 18 image with Docker networking
disabled. It checks the exact outbound reference query and runs the full
collector through a private Unix socket with Django 5.2.18 and psycopg2-binary
2.9.11. The test pins those versions to the reviewed
[Zentral constraints](https://github.com/zentralopensource/zentral/blob/88e67b3ce49033aab028029937a6e14f7c489073/requirements_constraints.txt).
The fixture uses Django's real auth and contenttypes migrations and synthetic
Santa app labels and models. It checks migration graph and applied rows, exact
comparison and duplicate rows, a custom table access method, quoted identifiers,
column tombstones, raw transaction refusal, statement timeout, interruption,
and rollback. It also reproduces the VM installer's schema default grants and
checks that comparison rejects a changed grant or an added database-wide grant.
An independent Unix-socket connection uses the restricted role. It confirms the
same row and migration observations and verifies that a disabled subscription
blocks collection. The catalog check counts subscriptions using their database
ID. The runtime role has no access to the connection-string column.
[PostgreSQL subscription catalog](https://www.postgresql.org/docs/18/catalog-pg-subscription.html)
The database and input data are disposable.

A separate lab run used the pinned Zentral core image and PostgreSQL 18.6.
Django 5.2.18 applied the image's migrations to a fresh database reachable
only through a private Unix socket. The census covered all nine configured apps,
121 registered models and 227 physical data relations, including sequences.
The census found no blockers in this fixture, a repeated observation matched,
and all eight authority table checks passed. The comparison used a baseline
and dispositions generated within the fixture. Independent coverage review,
referenced definitions, restore of the retained pilot archive, administrator and
device reissue, and native postflight still require evidence.

The Linux fixture also stops the synthetic cluster and checks the clean
shutdown through `pg_controldata`. It mounts the source volume read-only and
seals the full PostgreSQL directory, the pinned Elasticsearch node's native
snapshot, the pinned Redis node's multipart AOF and the drained RabbitMQ node
directory with Santa's cold backup writer. Control metadata and the media
volume use synthetic fixtures. The Linux check authenticates
and extracts the archive into private quarantine, copies only the quarantined
PostgreSQL directory to a fresh volume and starts PostgreSQL directly in a
separate network-disabled container. The restricted role compares the restored
rows, sequence state, schema and Django migrations
with the pre-shutdown census. It then changes a synthetic row and confirms the
comparison rejects the changed state. This covers the encrypted archive path
and physical PostgreSQL restore for the fixture. A fresh Elasticsearch node
registers the quarantined repository read-only and restores the selected
event index and alias. It checks both synthetic events and confirms the source
cluster's template was excluded. Separate lab runs authenticated and extracted
the retained pilot archive into volatile quarantine and started its archived
PostgreSQL cluster from a disposable copy. See the pilot-specific evidence
below for the database observations and remaining restore work.
[PostgreSQL file-system-level backup](https://www.postgresql.org/docs/18/backup-file.html)
[Elasticsearch snapshot restore API](https://www.elastic.co/docs/api/doc/elasticsearch/v9/operation/operation-snapshot-restore)

Redis history stays in quarantine. The fixture checks each captured AOF file
against its source digest. The pinned AOF checker opens files for writing, so
it receives a separate copy. The fixture confirms the checker changes no bytes.
A separate Redis instance starts from an empty directory. It initializes
a new store identity and admission generation, rejects the historical identity
and retains no old MFA claim or failure-budget key.
[Redis persistence](https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/)

The RabbitMQ fixture verifies a durable historical queue had zero ready or
unacknowledged messages before shutting down the broker. The encrypted archive
preserves the node data and Erlang cookie byte for byte in quarantine. A separate
empty broker starts with a fresh cookie and login. It rejects the historical
password and exposes neither the historical user nor the virtual host or queue.
Full application authority reissue remains open.
[RabbitMQ backup and restore](https://www.rabbitmq.com/docs/backup)

## PostgreSQL restore from the retained pilot archive

The independent verifier authenticated and decrypted the retained archive, then
matched its compatibility record to the local pinned PostgreSQL 18.6 image.
`pg_controldata` confirmed a cleanly shut down source cluster and
`pg_checksums --check` verified the archived data pages before startup.

The verifier started PostgreSQL directly on a disposable memory-backed copy
with fresh configuration, Docker networking disabled and a private Unix socket.
A read-only SQL transaction matched the running cluster identifier to the
archived identifier and read the `zentral` database. It observed 121 public
tables, including 24 Santa tables, and 236 Django migration records, including
51 Santa records. The test checked a clean shutdown, removed the containers and
volatile copies, and verified Azure VM deallocation. The receipt SHA-256 is
`04ba6c70d32e3094b0f8b8ab684badba82f03ebbea4fb5d5a7b4ea4e7a0d49f7`.

### Census of the retained pilot database

The original lab VM already held the exact Zentral image recorded in the
authenticated archive. The census ran that image with synthetic configuration
in its own network-disabled container. It read the disposable database copy
over a private Unix socket with read-only transactions.

Django 5.2.18 registered 121 models. The collector observed 720 catalog
relations, 227 data relations, 838 row observations including sequence state,
and 236 applied migrations. The supported catalog reported zero blockers.
All eight authority tables passed the shape check. A second census matched
the first with a shared ephemeral fingerprint key and fixture-generated
dispositions. The VM was deallocated after clean database shutdown and removal
of the temporary containers and memory-backed files. The receipt SHA-256 is
`dfbc09278c1c869607e48785223e6b055c2017a928d23aa983242e65db9ea8ce`.

The two observations came from the same quiescent restored copy. Comparison
against an independently reviewed source baseline, referenced-definition
coverage, application services and current-authority reconciliation remain open.

## Elasticsearch restore from the retained pilot archive

The independent verifier matched the authenticated compatibility record to
the pinned Elasticsearch 9.2.1 image and verified the captured snapshot UUID,
index selection, and shard inventory. It verified that a fresh node had no
indices, mounted a copy of the repository read-only and restored the captured
index with global and feature state excluded. The container used loopback
inside a network-disabled namespace. [Elasticsearch snapshot restore API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-snapshot-restore)

The restore returned one successful primary shard and zero failures. The
restored index returned 26 documents. The verifier checked that cluster
settings and repository bytes were unchanged, removed the temporary container
and memory-backed files, and verified VM deallocation. The receipt SHA-256 is
`6063b6c4f1d3f23c7ad93b751190b15fb123fea5921385702dbb2835aff509ec`.

The capture recorded index and shard inventory. Comparison of individual
documents against an independently captured baseline and integration with the
restored application remain open.
