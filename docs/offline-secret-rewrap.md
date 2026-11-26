# Offline secret-engine preservation primitive

`experiments/server/secret_rewrap.py` addresses the bounded offline portion of
[issue79](https://github.com/nathanmcnulty/azd-santa/issues/79). It has no CLI,
SQL, authentication, service activation, automatic file output or integration
with the installer/controller. It does not implement restore or establish
current authority. The complete [quarantine/reissue design](restore-quarantine-design.md)
and every unimplemented live acceptance gate still apply.

The explicit nine-app profile is accounts, realms, compliance_checks, incidents,
probes, stores, terraform, inventory and Santa, with the exact module names in
`APPS`. Different app profiles reject. This is a projection primitive: a future
quarantine caller must independently prove actual schema/migration/app coverage
and collect **every** encrypted row. Passing a caller-supplied app list and
context list does not prove that census. The primitive cannot detect omitted
database rows, unknown database columns absent from its input, or an inaccurate
description of installed applications. It must not be used as activation proof.

## Exact supported input and preservation

Inputs are complete concrete-row dictionaries for `stores.store`, `probes.action`
and `terraform.stateversion`, using the exact field sets exported by the module.
All three lists are required, including an explicit empty actions list when none
exist. Probe actions are an additional encrypted surface discovered in the exact
nine-app source census; omitting this model from future SQL collection is unsafe.
Store IDs are canonical UUID strings. StateVersion IDs are positive integer PKs;
foreign keys use their `_id` column names. Datetimes are confidential caller
projections (for example ISO strings); this component does not parse or change
them. M2M tables and every other model/history/configuration remain outside this
primitive and must be retained separately by the caller; they are not dropped
or treated as migrated. Unknown/missing fields, duplicate PKs, unknown store
backends, undeclared backend keyword names and unsupported engine material
reject the whole operation. The primitive never filters rows to obtain success.

The source lock enumerates the six Apache/core Store backends and their exact
`kwargs_keys`/`encrypted_kwargs_paths` declarations. Encrypted paths are:

| Backend | Paths relative to backend_kwargs |
| --- | --- |
| Elasticsearch | `password` |
| HTTP | `headers.*.value`, `password` |
| Kinesis, S3 Parquet | `aws_secret_access_key` |
| OpenSearch | `password`, `aws_auth.aws_secret_access_key` |
| ClickHouse | `password`, `access_token` |

Probe Action backends separately declare HTTP POST `headers.*.value`/`password`
and Slack incoming webhook `url`. Their encrypted `backend_kwargs` use
`{model:'probes.action', pk:<UUID string>, field:<actual path>}`; historical
probe/action relationships remain outside this projection and must be preserved.

Traversal retains identifiers, structure, list indexes, nulls and all other
values. It touches only declared secret paths; an unrelated dollar sign remains
literal. HTTP header entries accept only `name`/`value`; OpenSearch auth accepts
the pinned AWSBaseAuthSerializer fields. Unsupported nested secret shapes reject.
Store context is `{model:'stores.store', pk:<UUID string>, field:<actual path>}`.
Terraform context is `{model:'terraform.stateversion', pk:<integer>,
field:'encryption_key'}`. The ordered context inventory uses input row order,
source declaration path order, and ascending list indexes, omitting null values.
Store rows precede Action rows, followed by StateVersion rows. Missing, extra,
mismatched or differently typed contexts reject.

Every Terraform historical row is retained. Its wrapped per-version key is
rewrapped, while `data` stays byte-for-byte unchanged. Before returning, both
old and new keys decrypt that unchanged Fernet payload and bounded zlib
decompression must produce identical bytes. Malformed, unreadable, oversized or
unsupported history rejects instead of replacing the value or losing a version.

## Engine and interruption contract

Old/new engine names, password sequences and Django signing salts enter only
as in-memory `Material` objects. Explicit `targets` maps each old engine name to
a supported new engine. Historical Fernet passwords retain upstream MultiFernet
fallback order. PBKDF2-SHA256 uses 100,000 iterations, 32 derived bytes and the
exact signing salt, matching pinned Zentral. Different signing salts are tested.
Fernet-to-Fernet rewrap encrypts with the first new password and verifies recovered
bytes. Identical old/target material is permitted for preservation; success does
not prove key rotation or fresh authority. Explicit `noop` maps only to `noop` and preserves the original canonical
base64 token exactly, including empty values. Noop is cleartext encoding and
must remain confidential. No Fernet-to-noop downgrade or noop-to-Fernet policy
change is inferred. Unknown/KMS engines and inaccessible material remain gates.

**Pinned Fernet and noop ignore context cryptographically.** Selection inventory
checks only the intended model/PK/path; it cannot authenticate a token's original
location. A moved ciphertext that decrypts under the same material is not
detectable from this source format alone. Independently trusted row provenance
is a caller prerequisite. No signed inventory or new key service is invented.

The component deep-copies inputs and returns new private rows only after every
check succeeds. A late failure or interruption leaves all originals unchanged;
there is no partial file, transaction commit, overwrite, deletion or replay.
Returned rows remain sensitive and are excluded from `Result` repr. Its receipt
contains only bounded counts, the public source pin and explicit false restore/
current-authority flags. Exception text is fixed; the module prints nothing.
Python cannot promise secure erasure of immutable in-memory keys/plaintext; the
future caller must use an appropriately isolated, bounded recovery process.

Limits are 10,000 total rows, 32 MiB input string/byte content, 200,000 nodes,
depth32, 1 MiB per secret and 16 MiB per decompressed Terraform version, with
32 MiB total inspected plaintext. The caller must impose an outer process
deadline and prevent concurrent input mutation. Configuration validation here
is deliberately stricter than permissive upstream base64 decoding.

## Provenance and offline evidence

The source was acquired using `prepare_source.py`'s exact archive hash for
Zentral `88e67b3ce49033aab028029937a6e14f7c489073`.
`secret-rewrap-source.lock.json` records full raw upstream file hashes and the
reviewed declarations. Apache-2.0 test-only excerpts retain the upstream
Fernet/noop implementations, recursive Backend methods and StateVersion methods
in `tests/fixtures/server/secret-rewrap-upstream.json`; see
[third-party notices](../THIRD_PARTY_NOTICES.md). The new production module is
original Unlicense code and does not import Django or execute upstream services.
The fixture separates selected source bytes from test scaffolding. The Terraform
selection is the unchanged original lines50-78, including four-space indentation,
blank lines and comments, under a synthetic `class StateVersion` wrapper.
Every selection records its raw-file byte offset, length and SHA-256; the wrapper
prefix and its hash are recorded separately. The lock and tests check source
and combined harness hashes independently.

Tests use real cryptography and pinned engine/recursive traversal/get_data method
excerpts. They cover all six backends, nested headers, null/noop preservation,
historical Terraform versions, rotated password fallback and signing salts,
wrong keys/salts/selection contexts, unknown engines/apps/fields/backends,
malformed payloads, bounded decompression, late failures and interruption.
They do not execute Django ORM, SQL quarantine, a real restored database,
administrator reissue, KMS, current-authority reconciliation, native devices or
the full backup/restore lifecycle. No cloud permission is added.

On 2026-11-14, all14 focused Python tests passed with Python3.14.6 and
cryptography48.0.1 from the existing Azure CLI interpreter. The template
validation passed and the complete Pester6.2.0 suite passed231 tests under
PowerShell7.6.9. No dependency installation or live operation was performed.

## Secret coverage on the retained pilot database

The lab restored the authenticated pilot database into a disposable copy and
queried all three projections through the exact pinned Zentral image. It checked
the concrete model columns and matched the projection counts to the read-only
database census. The archive had one store, zero probe actions, and zero
Terraform state versions. The covered rows contained zero secret fields.

In the same image, a separate synthetic Fernet value was encrypted by Zentral,
rewrapped with a different password and signing salt, and decrypted by Zentral
using the replacement material. The database censuses before and after the
test matched. The runner removed its temporary containers and data, and Azure
confirmed VM deallocation. The receipt SHA-256 is
`17dadb54e4c1040c3a1e3b3302513c3f172b67b2d2a42535beb59e4689ca30c1`.
[Pinned Zentral Fernet implementation](https://github.com/zentralopensource/zentral/blob/88e67b3ce49033aab028029937a6e14f7c489073/zentral/core/secret_engines/backends/fernet.py)

## Transactional database adapter

`experiments/server/restore_secret_transaction.py` applies the verified
projection to an isolated recovery database. It uses two already-open private
Unix-socket connections, an independently selected recovery target, and an
independently reviewed census and secret context list. Keep all other writers
stopped. The adapter validates the exact three table shapes and holds table
locks while it compares the current census and verifies all replacements.

The preview returns a keyed digest binding the target, census, contexts and
old and new engine material. Applying requires that digest. PostgreSQL updates
only the selected JSONB leaves and Terraform wrapping keys. The adapter
re-reads the complete projections before commit. This preserves unrelated
JSONB values at PostgreSQL precision and leaves Terraform history bytes intact.
A failed write rolls back the transaction. An uncertain commit requires fresh
inspection before another recovery action.

The sealed PostgreSQL fixture exercises populated Store, Action and Terraform
projections, verifies old and new material binding, and forces a late write
failure to check rollback of earlier changes. A populated pilot archive,
independent coverage and provenance review, and application activation remain
separate qualification steps.
