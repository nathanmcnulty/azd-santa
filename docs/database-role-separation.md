# Fresh core database authority candidate

This fresh-only candidate for #61 has the selected private SQL, application and
reboot qualification recorded below. Earlier shared-role stack receipts remain
separate evidence. It adds no Azure service, Graph/Azure role or tenant grant;
automatic azd installation, production operation and existing-volume upgrades
remain separate gates.

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

`stage_runtime.py` now performs this explicit initialization for a fresh private
developer stack. Its CLI requires `--source`, `--lock`, `--destination` and an
immutable `--image sha256:...`; it no longer guesses an image from a mutable tag.
It checks the actual role-module/entrypoint bytes and execute mode, rejects an
existing project/network/volume namespace, and gates database, broker, Redis and
search readiness before one named owner job. Compose must support
`run --env-from-file`; that capability is checked before dependency startup.
Only the initializer receives `migration.env`, runs as container root, mounts
`runtime.env` read-only and writes to a private root-only receipt directory.
The driver retains an image/Compose/module/environment-hash binding before
launch; a timeout stops only the ownership-checked concrete helper ID and never
repeats initialization. A nonzero exit or missing completion receipt cannot
produce the final stage receipt. Subsequent authority/configuration/import checks
use only runtime credentials. This path starts no web listener or workers,
initializes no MFA cache marker and does not qualify SQL denials or application
behavior; those remain separate gates. Failed destinations/data must be retained.

The existing `Start-ZentralQualification.ps1` source uploader must include both
new database helper files before using the new core builder. Its exclusive
legacy paths are not a retry/upgrade mechanism. Fresh staging is not the
image-only `upgrade_core_runtime.py` path; existing volumes must not be adopted.

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

The harness passed on the selected fresh image below. Its empty-inventory scope
does not establish nonempty retention results. Failed/unknown initializer
outcomes still need actual fault qualification; their no-retry guards have
offline coverage. Nonempty cleanup, upgrades/default grants, existing-volume
credential migration and external backup/current-authority reconciliation remain
unqualified. Never give CREATEDB to runtime to make test-database creation pass.

## Actual private qualification, 2026-11-06

Fresh staging initialized the database through one owner-only job, then passed
runtime authority, Django and Store checks using `zentral_runtime`. The real SQL
harness passed original inventory TEMP cleanup and ten SQLSTATE 42501 denials:
permanent table creation/alteration/index/drop, migration-ledger writes, schema
creation, role creation/promotion, switching to owner and database creation.
The database-create denial used real autocommit. Security-store fresh admission
and its subsequent read-only check passed separately.

The selected immutable image is
`sha256:ebaff2f599f196b8f1902a9246afd0bd573a8b6c529a97607f7f893184271c92`.
Its build executed the modified entrypoint as the non-root image user, proving
the retained shebang and mode 0755. Database module SHA-256:
`f636a4128c3089c21d6a780ef32f2ed3fbda891e03a331e3ecbc02810d0d1322`.
Compose SHA-256:
`f15cdbd08c0784941e2b356fd871fa7bf3f85b580744f639206cbaa6af63c266`;
controller SHA-256:
`e662b57c4a55a38a27785daa99cc09a6dd8c9e9d6792cef0b60ec0a9ab0d4f0e`.

Normal runtime credentials passed full two-device Monitor sync, six-rule receipt,
89 HTTP request checks, indexing of two Santa events and all 15 MFA request cases.
The coordinated [receipt producer](https://github.com/nathanmcnulty/azd-santa/pull/68)
passed all six live readiness gates and generated the operator binding. The
supported setup entrypoint privately delivered bootstrap and targeted recovery;
independent readback preserved the synthetic operator's flags, changed its
password fingerprint and found the expected indexed audit records.

The separate [recovery fixture](https://github.com/nathanmcnulty/azd-santa/pull/69)
passed all 13 cases under `zentral_runtime`. Only owner fixture jobs created and
dropped the disposable database. Exact name/OID and no-active-backend teardown
completed, and an independent main-runtime query confirmed its absence. Its
audit posting is mocked; the real setup audit result above is separate evidence.

Clean stop closed the listener and stopped all seven original containers. A VM
reboot changed boot ID from `eec71322-01ca-4117-891b-0e7844a7c69e` to
`7d7121e3-ece3-4fc4-9e51-1ad8e0289a1e`. Independent post-start readback preserved
the container IDs, Santa state, checked identity/password/flag fields for 28
synthetic users, 16 TOTP seeds and one WebAuthn key/handle. A fresh Django-client
login with an existing preboot TOTP then
passed; password-only profile access remained denied. This is not held-session,
real-browser, trusted HTTPS or native Mac acceptance.

Private evidence is under
`/var/lib/azd-santa-qualification/runtime-santa-role-split-searchwait/`, including
`sql-role-receipt.json`, `role-foundation-ready.json`, `protocol-suite-ready.json`,
`operator-role-recovery-receipt.json`, `recovery-runtime-fixture/receipt.json`,
`role-reboot-before-receipt.json`, `role-reboot-after-receipt.json`,
`post-reboot-mfa-receipt.json` and `qualification-summary.json`.
All containers were cleanly stopped afterward; the unit remains enabled for the
next boot. The earlier `runtime-santa-role-split/` attempt stopped before owner
initialization because search was not listening. Its private receipt confirmed
no runtime role and zero public relations; its four dependencies and all data
were preserved. The bounded search wait fixes that demonstrated startup race.
