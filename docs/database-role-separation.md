# Fresh core database authority candidate

This is an offline-tested, fresh-only candidate for #61. No PostgreSQL, Docker,
VM, authentication or cloud operation has qualified it. Existing stack receipts
do not prove this new entrypoint, role layout or database grants. It adds no
Azure service, Graph/Azure role or tenant grant.

Fresh **core** preparation separates two local PostgreSQL login principals:

| Principal | Credential delivery | Authority |
| --- | --- | --- |
| `zentral_owner` | `db.env`; explicit privileged jobs through `migration.env` | Bootstrap, migrations/provisioning, upgrades and disposable test-database administration |
| `zentral_runtime` | `runtime.env` only, used by web/workers/Celery | Existing application tables DML, sequence usage, database CONNECT/TEMPORARY; no permanent schema ownership/CREATE, CREATEDB, CREATEROLE, SUPERUSER, replication, bypass-RLS or role membership |

`runtime.env` has six keys: `POSTGRES_USER`, `POSTGRES_PASSWORD`,
`ZENTRAL_DJANGO_SECRET`, `ZENTRAL_METRICS_TOKEN`,
`AZD_SANTA_SECURITY_STORE_ID`, `ZENTRAL_QUEUE_URL`. Its database password is
generated independently of `db.env`. `migration.env` has the same six-key shape
with owner database credentials; **no normal service references or mounts it**.
All output files are exclusive POSIX 0600 inside the fresh 0700 destination.
Existing directories/volumes are not updated or rotated. RabbitMQ retains its
two-key file and neither database service receives app signing/MFA/metrics keys.

The unmodified upstream-evaluation image/entrypoint retains the earlier shared
database role and five-key application file. It cannot use this restricted-role
startup contract. Its default upstream app profile remains unchanged. Core
preparation still defaults to Santa's app profile, including explicit upstream
app-profile override, seven services, five volumes and durable Redis settings.

## Explicit initialization, closed normal startup

The core builder checks exact pinned `docker-entrypoint.py` bytes before replacing
the three implicit migration/provision/admin-creation calls with
`operator_database check`. Input SHA-256:
`c11a6a75841a7c6f719367445a8d604a0cd8e4c9cfb39efe439d09999b2dbef7`;
output SHA-256:
`2789954887836f03fdc24bf42f0d12eb95109920f66911884200a95c3579a8f6`.
The original first-line shebang and second-line encoding cookie remain first;
the modification notice follows them. The replacement is installed mode 0755
because the pinned image's tini entrypoint executes that file directly.
The modified-source notice is retained and the image records input/output/module
hashes in `/zentral/server/DATABASE_ROLE_NOTICE.json`. Apache/core and original
Unlicense provenance remain separate. No EE source is added.

Normal app startup now checks the actual connected identity, role attributes,
membership, ownership and effective privileges; the migration ledger must be
read-only to runtime. It then requires no pending migrations and the expected
provisioned Elasticsearch Store. Failed checks exit before the normal listener
or worker command. There is no automatic migration, role repair, credential
rotation, operator bootstrap or database initialization.

The explicit management command `operator_database initialize` runs only with the
owner credential against database `zentral` at host `db`. A future hash-bound
deployment job must select the exact runtime/image, use `migration.env`, supply
the selected runtime file as a root-owned read-only private mount, and provide
an absent private receipt path. These are orchestration internals, not manual
customer setup steps. The one-command azd flow must perform them before service
admission; that orchestration and upgrade path are still unimplemented.

Initialization reserves and fsyncs an unknown-outcome checkpoint before database
mutation, takes a session advisory lock and requires a fresh database, absent
runtime role and expected database owner. It runs migrations/provisioning under
owner authority, rejects foreign object ownership and public SECURITY DEFINER
functions, creates the restricted role with structured psycopg2 identifiers and
password literal, and grants existing-table/sequence and owner-default privileges.
It independently authenticates with the runtime password and checks actual
permissions. Success is a separate exclusive checkpoint; failure never causes
automatic retry or overwrites an existing role/password. Partial migration or
commit failure requires private inspection and deliberate fresh qualification.

The host setup attestor now requires the six-key runtime file, expected distinct
owner/runtime usernames and different passwords. Old shared-role/app-five-key
containers cannot silently pass. Existing bindings/images must be preserved;
this candidate requires new qualification, not in-place adoption.

## Temporary cleanup and search path

Pinned core source `88e67b3ce49033aab028029937a6e14f7c489073` uses an actual TEMP
table, index and ANALYZE in `zentral/contrib/inventory/utils/cleanup.py:24-41`,
invoked by ordinary `inventory/tasks.py:25-37`. Database TEMPORARY is therefore
an explicit permission, not a silent substitute for permanent-schema CREATE.
Cleanup, UI and Celery behavior are preserved. Runtime may own its temporary
objects; it owns no permanent application schema/table/function or database.
Its search path is `pg_catalog, public, pg_temp`; permanent schema creation and
role membership remain denied. Permanent-schema CREATE/ownership checks include
system schemas, exempting only catalog-identified temporary schemas (including
the current session's temporary TOAST namespace). PostgreSQL's
[namespace implementation](https://github.com/postgres/postgres/blob/REL_18_STABLE/src/backend/catalog/namespace.c)
distinguishes that namespace from other sessions' temporary namespaces.
Initialization/runtime checks reject non-system
SECURITY DEFINER functions; there are none in the inspected pinned migrations.

## Required live acceptance

`test_database_roles_live.py` is an opt-in, source-module-bound harness for a
fresh, empty private application database. It calls the original inventory
cleanup (TEMP table/index/ANALYZE/drop) under runtime credentials and requires
real SQLSTATE 42501 denials for permanent CREATE/ALTER, schema creation, role
creation/promotion, switching to owner and CREATE DATABASE. The database-create
probe uses actual autocommit, so a transaction restriction cannot fake a denial.
Other probe mutations are rolled back; a unique unexpectedly created probe
database is removed before failing. Its output is a bounded nonsecret result.

This harness has **not run**. Its empty-inventory scope does not establish
nonempty retention results. Fresh bootstrap and failure receipts, normal HTTP
sync/indexing/MFA/recovery, restart/runtime-role admission, nonempty cleanup,
upgrades/default grants and separate owner-authorized developer test jobs all
remain required real acceptance gates. Never give CREATEDB to runtime merely to
make Django test-database creation pass. No existing-volume credential migration
or external backup/current-authority reconciliation is implemented.
