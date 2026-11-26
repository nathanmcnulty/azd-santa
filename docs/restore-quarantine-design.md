# Restore quarantine and fresh-authority reissue design

This document describes the isolated database recovery steps and the design for
fresh authority reissue. The Azure pilot completed separate signed rewrap and
authority quarantine steps on one restored PostgreSQL copy. Rewrap preserved the
source census. Quarantine neutralized two authority rows and preserved all 838
rows, the catalog, applied migrations and the other 226 relations. Activation
remained closed. [Azure pilot evidence](https://github.com/nathanmcnulty/azd-santa/issues/53#issuecomment-7195096868)

The same Azure pilot created one fresh administrator and returned the sealed
setup link through Run Command. Durable key custody, customer-facing recovery
orchestration, browser setup, device reissue and service activation remain open.
[Live administrator evidence](https://github.com/nathanmcnulty/azd-santa/issues/53#issuecomment-7196648755)

The separate `experiments/server/restore_cipher.py` primitive now authenticates
the existing sealed format against an externally trusted ciphertext digest and
recipient key. It discards decrypted chunks and returns only after complete GCM
tag and digest verification. It creates no plaintext file, parses no archive and
never restores or admits a service. Eight synthetic crypto tests cover producer
roundtrip, tampering, truncation, recipient/digest/header/size/deadline failures.
The [authenticated archive quarantine primitive](authenticated-archive-quarantine.md)
adds bounded private extraction with producer-format checks and inert ownership
and mode metadata. The Azure pilot exercised this path on Linux using the retained
encrypted archive. Crash and interruption cases remain separate qualification
work. The caller obtains the expected digest from trusted external evidence and
bounds blocking I/O with an outer process deadline.

The proposed initial scope is a quarantined restore of the known Santa profile,
followed by new identities and credentials. Preserve the original backup and
restored history. Never reactivate restored identities or silently reuse old
queues/configuration. Authority to initiate this privileged operation must come
from the currently selected external Azure ARM operator and current target
readback, not a user, role, credential, marker, receipt or claim in the backup.
Cached ARM identity alone is not a restore implementation or authorization
receipt: the eventual command must bind explicit current authorization, exact
target, reviewed source and backup digest before mutation.

## Exact source binding

The inventory was inspected against raw upstream commit
`88e67b3ce49033aab028029937a6e14f7c489073` in
[zentralopensource/zentral](https://github.com/zentralopensource/zentral/tree/88e67b3ce49033aab028029937a6e14f7c489073).
Ranges below refer to raw upstream files, not patched image sources. The Santa
model file has **2238 lines**. A different-length copy must not be treated as
matching evidence without comparing its bytes.

| Upstream source | SHA-256 |
| --- | --- |
| `server/accounts/models.py` | `ef6335ee2845234997770a37203ca21c1b4d67625a594163a4f1718ac917511d` |
| `server/realms/models.py` | `3bc32d938c4a48ff9ff90bdc07f959ba16c63cd0e3ac4ed87e9c5623609cf038` |
| `zentral/contrib/inventory/models.py` | `c0f3dbeaca491ca1b6d98dd38d3f3456ee71e4d2de6b51fb9ee735dcd1ec626e` |
| `zentral/contrib/santa/models.py` | `5494304144e100d21abadf4bf12e478d5746f6bd427e796abde4b70094057ee8` |
| `zentral/core/stores/models.py` | `4c99ad608fa0a9375838ac474014ab990d5ae63327a8270d406399c3c24dc25d` |
| `zentral/core/terraform/models.py` | `c64fd013f6ab38160b3c1c2f5579227590d1b408498cbb37a119d08abd9cb6aa` |
| `zentral/core/secret_engines/backends/fernet.py` | `0429f8298bbb382260f76c8448e061988d5633cb727dad36484e396794712cf4` |
| `zentral/core/secret_engines/__init__.py` | `253f248dea651940489b60b2708cbb68ee7ac31344715e72b2c632a3fd8912dc` |
| `zentral/utils/backend_model.py` | `d0b6c1b7d46f42b1c14b6353914e0e4397c2f37dd9f33ace0394a06fa870a11d` |
| `server/accounts/provisioning.py` | `b11ec520ef9366fe1f216cd4470b78e09629d7e595b893159be2c999ea6dcb31` |
| `server/server/settings.py` | `1f302e91ed35a170e1580a8c79c218bb812c6efc09f7850bb41392f9ce6bd2b1` |

The eventual job must also bind the installed original policy modules, compiled
core patches, actual image, configuration and migration state. The raw upstream
inventory alone does not attest installed behavior.

## Database authority inventory

These are Django's default table names for the inspected models. The eventual
implementation must assert actual `_meta.db_table`, columns, constraints and
migration state before mutation, rather than execute SQL against guessed names.
This is an authority inventory, not a complete database schema manifest.

| Tables / fields | Required disposition before listeners |
| --- | --- |
| `accounts_user`: `is_active`, `password`, `is_superuser`, `is_staff`, `is_remote`, `is_service_account`; accounts lines35-85 | Disable every restored user, including superusers and service accounts, and assign unusable passwords. Preserve original records/flags as inert history. Create the authorized current administrator with a new PK and explicitly supplied privileges, without inherited roles. Never reactivate old identities. |
| `accounts_user_groups`, `accounts_user_user_permissions`, `auth_group`, `auth_group_permissions`, `accounts_provisionedrole`; accounts245-248 | Preserve historical memberships; do not attach them to new identities. `accounts/auth_backends.py:17-90` bypasses legacy Django permissions; Cedar is the effective authority. |
| `accounts_policy`: `is_active`, `source`, `provisioning_uid`; accounts415-490 | Set all restored policies inactive. Remove restored role/policy provisioning from active configuration so provisioning cannot reactivate them. Fresh policies require separate approval. |
| `accounts_apitoken`: `user_id`, `hashed_key`, `expiry`; accounts265-319 | Expire every token, retaining rows and any already-earlier expiry. Disabled users provide an independent denial boundary. Signing-key rotation alone does not revoke these hashed random tokens. |
| `accounts_oidcapitokenissuer`: `user_id`, `issuer_uri`, `audience`, `cel_condition`, `max_validity`; accounts322-381 | No enabled field exists. Set restored `cel_condition='false'`, retaining original conditions in encrypted evidence; keep associated users inactive. The issuer auth serializer at `accounts/serializers.py:97-160` otherwise can mint tokens for inactive users, although API authentication rejects their use. |
| `accounts_usertotp`: `secret`; `accounts_userwebauthn`: `key_handle`, `public_key`, `rp_id`, `sign_count`; accounts189-242 | Preserve as inert history attached to inactive old users. Do not copy factors to new identities. The new administrator must enroll fresh MFA. These fields are not secret-engine encrypted by these models; TOTP secrets remain sensitive backup contents. |
| `django_session`: `session_data`, `expire_date` | Expire all restored sessions. A new signing key with no old fallbacks, fresh Redis and fresh MFA enrollment also invalidate captured session/challenge authority. |
| `realms_realm`: `enabled_for_login`, `user_portal`, `scim_enabled`, `backend`, `config`; realms21-105 | Set all three enable flags false. Do not reactivate restored realm configuration or provisioning. Backend config can contain credentials and must remain confidential. |
| `realms_realmauthenticationsession`: `expires_at`, `backend_state`, callback fields; realms325-379 | Expire all sessions, including previously unbounded sessions. |
| `realms_realmuser`, `realms_realmgroup`, `realms_realmusergroupmembership`, `realms_rolemapping`, `realms_realmgroupmapping`; realms116-287,382-414 | Preserve inertly; fresh realms/groups must not inherit these role mappings. |
| `inventory_enrollmentsecret`: `secret`, `revoked_at`, `expired_at`, `quota`, `request_count`, serial/UDID restrictions; inventory1428-1517 | Revoke all restored secrets, not merely known pilot rows. Preserve existing revocation timestamps, quota/counts and restrictions. Issue genuinely new secret rows later. |
| `santa_enrollment`: `secret_id`, `configuration_id`, distributor fields; Santa1220-1235 and inherited inventory1529-1547 | Preserve, but never connect new credentials to restored configurations automatically. |
| `santa_enrolledmachine`; Santa1323-1598 | Preserve device/session/counter history. The installed continuing-sync guard must reject revoked enrollment secrets at all four stages. Do not reset quota or implicitly reenroll devices. |
| `santa_configuration`; Santa541-975 | Preserve old configurations as unreachable history. New enrollment uses a new Monitor configuration without inherited paths, voting, transitive behavior or USB enforcement. |
| `santa_scopedclientmode`, `santa_scopedpathregex` and their tag/excluded-tag tables; Santa1022-1182 | Preserve but do not copy or reattach to the new configuration. Includes serial, primary-user, tag and exclusion targeting. |
| `santa_rule`, `santa_rule_tags`, `santa_rule_excluded_tags`, `santa_ruleset`, `santa_machinerule`; Santa1659-1820,2207-2238 | Preserve complete policy/version/CEL/targeting and staged/committed ledgers. There is no generic rule disabled flag. Isolation depends on revoked old enrollments and a new configuration without inherited rules. |
| `santa_votinggroup`, `santa_ballot`, `santa_vote`, `santa_targetstate`; Santa1185-1217,1604-1656,405-437 | Preserve voting history/state, but keep old realms and portals disabled; the new configuration has no voting realm/groups. Preserved votes must not regenerate active rules. |
| `stores_store`, `stores_store_events_url_authorized_roles` | No enabled field exists. `stores/conf.py:48-73` loads every store, even with `admin_console=False`. Initially support only the reviewed single private Elasticsearch store with exact approved backend/endpoint/config; abort on additional or unknown stores. Generic preservation-compatible disabling needs additional reviewed integration. |
| `terraform_stateversion`: `encryption_key`, `data`; Terraform32-78 | Preserve both fields and every version. Data uses its per-version encryption key; losing the wrapped key loses recoverability. |

The job must not depend on model save signals for coverage. QuerySet/bulk/raw
writes can bypass save hooks; Santa voting also writes rules through raw SQL.
The proposed operation runs with all writers stopped and verifies its own final
authority predicates. A later signal-based external head would require a
separate inventory of all write paths and coordinated commit behavior.

The in-memory authority planner in `experiments/server/restore_authority_plan.py`
defines the update allowlist for the eight affected models. It accepts typed
projections and counts from the caller's reviewed census. It plans inactive
users, Cedar policies and realms, unusable passwords, expiring tokens and
sessions, denied OIDC conditions, and revoked enrollment secrets. It retains
earlier expiries and existing revocation timestamps. The pinned realm model
can use a realm-level login session lifetime, so a session timestamp is only
one part of the planned realm changes. The private plan includes a keyed
fingerprint of the observed projections and a receipt with per-model counts.
It performs no database writes. A transactional adapter must still bind
the actual schema, target, writer quiescence and independently reviewed
census before these updates can be used. Zentral uses naive UTC datetimes.
The adapter must establish that database time zone and normalize timestamps
before passing them to the planner.
[Pinned Zentral realm session model](https://github.com/zentralopensource/zentral/blob/88e67b3ce49033aab028029937a6e14f7c489073/server/realms/models.py#L299)
[Pinned Zentral time settings](https://github.com/zentralopensource/zentral/blob/88e67b3ce49033aab028029937a6e14f7c489073/server/server/settings.py#L218)

The transaction adapter in `experiments/server/restore_authority_transaction.py`
supports an already-isolated PostgreSQL 18 recovery database over a local Unix
socket. The caller supplies two open connections, the independently selected
database identity, the reviewed census, and exclusive control of application
and maintenance writers. The adapter checks both sessions against the same
database OID, cluster, server start, role and socket. One session locks the
eight authority tables while the second reruns the full read-only census.
Preview returns a digest. Apply rechecks that digest before updating every
planned row in one transaction and verifies the resulting projections before
commit. Unsupported table structure, other target clients, drift or a failed
write stop the operation. An uncertain commit requires inspection.
[PostgreSQL table lock semantics](https://www.postgresql.org/docs/18/sql-lock.html)

The hosted fixture covers the eight dispositions, preservation of unrelated
fields, rejection of a stale review, and rollback when the final table
rejects a write. This adapter neither controls external writer isolation nor
admits listeners or reissues credentials. The complete Zentral registry,
external authority, and live restored-service tests remain separate.

## Signing rotation and secret recoverability

The separate [offline secret-rewrap primitive](offline-secret-rewrap.md) now
checks complete Store/probe Action/StateVersion row projections with real Fernet/noop
preservation tests. It provides no SQL census, restoration, activation or
current-authority proof. The future quarantine workflow must still establish
complete schema/row coverage and every authority gate below. Pinned Fernet/noop
cannot cryptographically authenticate a token's original context.

Do not rotate `SECRET_KEY` and assume encrypted data survives. The pinned Fernet
backend at lines10-24 derives keys using PBKDF2 with `settings.SECRET_KEY` as
salt. Keeping the same configured passwords, or setting `SECRET_KEY_FALLBACKS`,
does not preserve those Fernet decryption keys.

Before changing active signing configuration:

1. Census encrypted fields and engine prefixes without publishing values.
2. Retain the old signing salt and secret-engine passwords/KMS access in
   restricted recovery material.
3. Offline-decrypt using the old engine and exact context; reencrypt with the
   new engine/signing salt.
4. Privately prove equivalent plaintext and readable nested data.
5. Commit transformed rows and configuration binding before allowing apps.

For the nine-app Santa profile, inspected encrypted data surfaces include:

- `probes_action.backend_kwargs`: HTTP POST headers/password and Slack incoming
  webhook URL, declared by the pinned `probes/action_backends` classes. These
  share BackendInstance's recursive model/PK/path context and must be collected
  along with stores; preserving action rows and probe relationships is required.

- `stores_store.backend_kwargs`, recursively traversed by
  `zentral/utils/backend_model.py:35-87`. Context is model, PK and field path;
  preserve exact list indexes and identifiers.
- Store backend encrypted paths: Elasticsearch password; HTTP password and
  header values; Kinesis/S3 AWS secret; OpenSearch AWS secret; ClickHouse
  password/access token. Inspect the exact selected backend's
  `encrypted_kwargs_paths`; do not guess paths from field names.
- `terraform_stateversion.encryption_key`, with context
  `{model:'terraform.stateversion', pk, field:'encryption_key'}`. Verify
  `get_data()` still decrypts/decompresses the unchanged data field.
- Tokens identify their engine using `engine$payload`; secret-engine dispatch
  is at `zentral/core/secret_engines/__init__.py:75-111`. Historical engine names
  are required for decoding.
- The generator's default configuration does not configure a secret engine and
  upstream defaults to `noop`. Do not infer arbitrary restored data uses noop.
- KMS engines depend on external keys and context; unknown engines/backends or
  inaccessible keys keep restore closed.

Optional/older applications add encrypted fields, including Jamf credentials,
repository backend kwargs and MDM keys/command payloads. The initial workflow
must reject unsupported installed-app/schema/config combinations rather than
omit records or claim complete rewrap coverage. Retain original backup and old
decrypt material until every applicable field has been checked. Hash/count
receipts alone do not establish decryptability. Do not log plaintext secrets or
replace undecipherable values with blanks to make startup pass.

## Other active-generation material and preservation gates

- Use a new `ZENTRAL_DJANGO_SECRET` and empty `SECRET_KEY_FALLBACKS` after the
  encryption migration. Both reset and invitation links use the upstream
  password-reset token mechanism (`accounts/password_reset.py:34-46`); old
  links and pending MFA challenges must fail independently of restored clocks.
- Generate a new metrics bearer token.
- Use a new private security-store ID and explicitly initialized Redis
  generation. Restored markers/replay/budget state are not current authority.
- Use fresh broker credentials and fresh Rabbit state, retaining restored
  broker data offline. Old queue/Celery tasks must never execute against the
  reissued database authority. Their preservation is not permission to replay.
- Rotate and validate PostgreSQL owner/runtime credentials and the full local
  role inventory. Physical PostgreSQL restore also restores role/password
  catalogs; changing env files alone does not rotate them.
- Produce newly attested source/image/Compose/container generation and setup
  bindings. Do not reuse old sealed-operation/readback bindings.
- Bind current approved TLS/trust material and origin/proxy configuration. Do
  not automatically activate restored CA/private-key or remote-auth config.
- Reject unknown stores before any application or worker starts. Existing
  `admin_console` or role restrictions do not disable outbound store delivery.
  Preservation of historical Elasticsearch data is distinct from authorizing
  restored external destinations or credential use.
- Remove restored role/policy/realm provisioning from active configuration.
  `accounts/provisioning.py:13-38` and `zentral/utils/provisioning.py:35-76`
  create/update configured objects and can undo database-only quarantine.

Original backup volumes and records remain available for forensic recovery.
No history/rule/config/token/factor deletion, queue purge or dropping unknown
tables is justified merely to simplify the supported workflow. If broader data
cannot be preserved safely, the variant remains unsupported and admission stays
closed. Quarantining authority necessarily changes active authority fields;
retain the original encrypted backup and a private pre-change inventory.

## Proposed operation boundary

Use one explicitly authorized restore job while all applications and queues
remain stopped. A new restore-quarantine command is required: existing fresh
security initialization rejects databases containing users, while existing
operator recovery refuses inactive users and preserves privileges. Neither is
a shortcut to this workflow.

1. Validate current external operator/target authorization, exact backup/source
   binding, schema/app/key-engine/store coverage and preserved data inventory.
2. Complete encryption preflight/migration; abort without activation on any
   unreadable field. Use safe model/identifier APIs and preserve engine context.
3. In one database transaction, lock affected authority tables, disable users,
   policies and realms, invalidate passwords/sessions, expire tokens,
   neutralize OIDC CEL and revoke all enrollment secrets. Preserve existing
   earlier expiry/revocation evidence and history.
4. Commit a private generation-bound quarantine result with counts and
   nonsecret predicates, not credentials or plaintext comparison values.
5. Bind new configuration, DB credentials, Redis and broker generations. This
   is not atomically transactional with PostgreSQL. Any interruption leaves
   listener admission closed and requires inspection; no automatic replay or
   rollback to old credential authority.
6. Create one explicitly authorized new local administrator, require fresh MFA,
   then reissue only approved new service accounts, policies, realms and device
   enrollments. New identities have new PKs; restored roles do not confer new
   privileges. Monitor mode remains mandatory.

The opt-in recovery tooling bundle v4 includes a Python journal for the two
database steps. The trusted caller selects one persistent owner-only directory
for the exact restored database, archive hash and recovery generation. Each
step has its own preview digest. Apply records and flushes the intent before
writes and adds a committed record after the transaction returns and a
post-commit census succeeds. The following step requires an independent review
of the exact census fingerprint recorded by the previous step. A database
restart changes the target binding and requires inspection.

Journal status reports `pending`, `committed`, or `inspect` for each step. An
intent without a valid committed record requires private inspection of the
isolated database, even when an adapter reported an error. Keep the journal
and original archive during inspection. The journal never enables activation.

Restore tooling bundle v23 includes a guard for issuing one fresh administrator.
The guard requires the authenticated quarantine receipt and a new census that
matches the committed post-quarantine state. Its approval binds the selected
recovery job, new administrator identity, fresh runtime, and setup recipient.
It records intent before calling the trusted administrator creator. When
the creator returns a confirmed sealed artifact digest, the guard records
completion. Inspect the original attempt if the result is uncertain. Service
activation stays closed.

Restore tooling bundle v24 adds the administrator creator. It rechecks the
committed census under a database lock on the isolated PostgreSQL instance,
requires all archived users to be inactive, and creates a fresh local account
with no inherited roles or factors. It seals the existing ten-minute
administrator setup link to the approved recipient. The transport can read
the original ciphertext after the account commit and journal completion.
Restore tooling bundle v25 requires a three-minute Ed25519 approval for
the exact administrator plan, including the HTTPS setup origin digest.
The operator checks the selected Azure account and VM immediately before
signing. The receiver verifies the signature against the operator key
digest pinned independently by its launcher.

Restore tooling bundle v26 adds the Azure Run Command handoff. The launcher
pins the plan and key in a private receiver directory. Run Command deposits
the signature once. The isolated worker consumes it and publishes the
original encrypted setup artifact after the reissue journal confirms commit.
The operator can read the outcome using the original approval digest after
a lost response. Readback never recreates the account or the setup link.
The one-receiver Azure drill used an isolated launcher and exercised live
delivery and ciphertext readback. Browser setup and service activation remain
separate gates.

Restore tooling bundle v27 initializes the MFA and Santa admission records in
a dedicated fresh Redis database after checking the committed quarantine census.
Its plan binds the selected Redis process, runtime, store identity and admission
generation. One Lua operation rejects any existing key and writes both new
records. The worker confirms the new generation with zero active permits before
recording completion. A missing result requires inspection. The recovered
runtime stays closed during this step.

An isolated Azure drill initialized that Redis generation and exercised the
restored operator's original setup link through Django's request handlers.
The app rejected reset replay and required TOTP before granting profile
access. The drill stubbed static asset resolution and intercepted audit
delivery. A TLS browser session and service activation remain separate.
[Live restored MFA evidence](https://github.com/nathanmcnulty/azd-santa/issues/53#issuecomment-7197526783)

A subsequent isolated restore on the 4 GiB Azure receiver kept the signed
database and administrator steps and added the real Zentral event workers.
Fresh RabbitMQ started with no queues. The workers delivered one synthetic
audit event to the restored Elasticsearch index, preserving all 26
historical documents and the retained snapshot repository. The queues
drained, PostgreSQL shut down cleanly, and the temporary restore and
containers were removed before the receiver was deallocated. The test
used a 256 MiB Elasticsearch heap and capped Elasticsearch and RabbitMQ at
896 MiB and 320 MiB, respectively. The drill kept all ports unpublished.
[Live restored event delivery](https://github.com/nathanmcnulty/azd-santa/issues/53#issuecomment-7199797115)

A subsequent drill stopped the event worker before starting the pinned Celery
process on the same 4 GiB VM. At a 384 MiB memory limit and concurrency one,
Celery consumed one synthetic JSON task on a dedicated queue in fresh RabbitMQ.
The exact successful task result was read from restored PostgreSQL. The queue
drained, Celery shut down with exit zero, and the receiver was deallocated.
[Live restored Celery task](https://github.com/nathanmcnulty/azd-santa/issues/53#issuecomment-7200272734)

An isolated HTTPS drill brought up the recovered Gunicorn service, served a
compiled stylesheet, and used the sealed one-time setup link over a socket
validated against a private test certificate. The app trusted the exact
fixture origin. It rejected a foreign origin and a missing CSRF token,
accepted the reset, and rejected replay in a fresh client. The recovered
administrator enrolled TOTP and could open the profile only after verification.
The temporary service and database shut down cleanly.
[Recovered HTTPS sign-in](https://github.com/nathanmcnulty/azd-santa/issues/53#issuecomment-7201591941)

A controlled repeat on the 4 GiB Azure VM gracefully stopped the original
seven-service lab stack and kept its startup configuration enabled. The
recovered HTTPS service, event workers and Celery ran concurrently with
restored PostgreSQL and Elasticsearch and fresh Redis and RabbitMQ. The drill
verified the administrator reset and MFA over loopback HTTPS, indexed one new
event alongside 26 restored documents, drained the event queues, and read the
result of one private-queue Celery task from restored PostgreSQL. The lowest
sampled available memory was 1,416,468 KiB (about 1.35 GiB). The retained
snapshot stayed intact. Workspace cleanup and Azure deallocation completed.
[Concurrent recovery drill](https://github.com/nathanmcnulty/azd-santa/issues/53#issuecomment-7202850496)

Sustained load, failure handling, human browser validation, public certificate
lifecycle, native-device recovery and repeatable azd activation remain open.

Recovery tooling bundle v5 includes the private census review handoff. The
reviewer exports the complete dispositions and keyed census fingerprint,
bound to the exact target, archive, generation and step. Share the document
privately and deliver its SHA-256 through a separately trusted channel.
The launcher compares the document and a fresh census before requesting a
preview. An apply requires the preview digest and a positive current
authorization check for that exact review and operation before journal intent.
The document carries no database rows or credentials. A matching digest only
establishes the integrity of the selected review. The launcher must obtain the
expected digest and current authorization from outside the backup.

For the initial review of a cold copy with a reserved recovery database
name, pass the independently collected source census and its dispositions to
the publisher with the original `source_database`. The publisher verifies
the source census fingerprint and the same database role, then updates only
the database-name fact and that fact's disposition key. A subsequent census
must match all projected facts. Keep the original census private. Capture
provenance and stopped-writer evidence are still required to establish that
the independently collected census represents the archived source.

Recovery tooling bundle v6 includes the cached Azure operator readback for the
trusted launcher. It binds one explicit confirmation to the step, review,
plan digest and restored database binding. Before accepting it, the adapter
uses Azure CLI to verify the configured user, tenant and subscription around
a live read of the exact Santa pilot VM resource and instance ID. A mismatch,
expired confirmation or failed read closes the attempt. The readback grants no
permission and is insufficient to authorize VM execution on its own.

Recovery tooling bundle v7 includes `restore_guest_readback.py`. It plans
offline by default. An explicit `--live` runs one fixed guest probe on the
selected VM using existing Azure Action Run Command rights. The probe checks
instance metadata and returns a nonce-bound Linux boot ID. The caller checks
the Azure account and exact VM before and after the command. The receipt
contains no secrets and does not include a database observation.

Recovery tooling bundle v8 connects the verified guest readback to the
isolated database job. Both census reviews, the exact operator confirmation,
and journal records bind to the same tenant, operator, VM resource, instance,
boot, archive and database. The job checks the live PostgreSQL target before
preview or apply. The launcher must keep the journal and operation generation
consistent across the two steps.

Recovery tooling bundle v9 seals the private review, fingerprint key and step
options to a short-lived guest recipient. The receiver authenticates the packet
against the exact offer and independently pinned ciphertext digest, then passes
the inputs in memory to the reviewed job. The offer is bound to the boot,
database job, review and plan. A matched packet gets one decryption attempt.
The recipient and packet confer no operator authority. Apply still requires a
positive current authorization check under the journal lock.

Recovery tooling bundle v10 can carry that ciphertext in one object in the
selected private backup store. The object key includes the packet digest.
The sender reserves a private journal before a create-only conditional PUT.
The selected VM reads the object with a separate read-only capability and
verifies the independently supplied digest and length before decryption.
An ambiguous upload can be reconciled by readback. The sender does not
resubmit the PUT. [Azure Blob conditional requests](https://learn.microsoft.com/en-us/rest/api/storageservices/specifying-conditional-headers-for-blob-service-operations)

Recovery tooling bundle v11 issues the two capabilities using the selected
cached Azure user and fresh readbacks of the owned store and both lab VMs.
Use a separate reservation for each role. The sender receives create-only
access and the recovery VM receives read-only access to the same exact packet.
The issuer keeps the SAS values in memory. The reservation records the target
and object so an unknown issuance can be inspected. [Azure List Service SAS](https://learn.microsoft.com/rest/api/storagerp/storage-accounts/list-service-sas?view=rest-storagerp-2025-06-01)

Recovery tooling bundle v12 seals each SAS to the public offer from its
intended sender or receiver. The caller supplies the verified boot and
owner-private temporary directory. The guest checks the packet object and
operation role, then records consumption and removes its private recipient
key before using the capability. A lost transfer response requires inspection
of the reserved operation. The SAS stays out of command arguments and receipts.

Recovery tooling bundle v13 carries the public offer and encrypted SAS through
the existing Action Run Command transport. The caller selects a reviewed
tooling bundle and an exact sender ciphertext file. The command splits the
source capsule into bounded requests and the guest verifies its hash before
loading it. Each request checks the selected Azure operator and VM on both
sides and requires a fresh completion marker. The receiver writes verified
ciphertext to a private, boot-local file and returns its digest and byte count.

Recovery tooling bundle v14 also stages sender ciphertext automatically.
The command sends bounded packet parts after verifying the full input digest.
The guest checks the expected boot, part order and digest, and publishes the
file only after verifying its full size and SHA-256. The sender can still use
an exact file already present inside the private network. Run Command stages
one request per part, so transfer cost and time grow with packet size.

Recovery tooling bundle v15 adds the `restore_packet_operator.py` launcher.
Use `plan` with the selected private-store receipt, trusted job metadata,
encrypted packet and pinned tooling bundle. The metadata carries the operator
account, sender boot, receiver receipt, PostgreSQL target, archive digest, and
recovery generation. Supply the displayed plan digest and an owner-private
journal directory to `apply`. The launcher stages both guests, delivers the
credentials in order, uploads once and independently verifies the receiver.
A lost upload acknowledgement can be reconciled by a matching readback.
Use `observe` to inspect local journal evidence without a cloud request.
The two selected guests stage their tooling and obtain offers concurrently.
Both must complete before any SAS is issued. The sender upload and
independent receiver readback still run in order.

After an interrupted transfer with a durable upload attempt, start only
the original receiver on a new boot. Use the original store selection,
job metadata and pinned tooling with the recorded plan and packet digests.
The retry needs neither the sender VM nor a local copy of the packet.

```powershell
python ./experiments/server/restore_packet_operator.py readback `
  --selection $selectionPath --job $jobPath --tooling $toolingPath `
  --operation $operation --commit $commit --tooling-sha256 $toolingSha256 `
  --packet-sha256 $packetSha256 --plan-sha256 $planSha256 --journal-root $journalRoot
```

The retry issues a read-only SAS and stores its intent and result in a
separate directory named for the new boot. Preserve that directory if
the guest returns no verified result. The original journal stays intact,
and no create SAS or second upload is attempted. The readback receipt
proves object integrity. Applying a database step on the new boot
requires a fresh review, recipient offer and sealed packet.

Recovery tooling bundle v16 connects the approved delivery to the existing
isolated database job. The receiver requires the trusted plan digest and a
matching verified transfer receipt. It opens the exact owner-private file
under the selected receiver capsule and rechecks size and SHA-256 before
decryption. The existing offer and journal still gate each database step
and require current authorization.

Recovery tooling bundle v17 lets the operator sign the exact reviewed
database step after a fresh Azure Resource Manager authorization check.
The Ed25519 signature binds the guest offer, stage, transfer plan and
receipt, and ciphertext for the selected receiver. It expires within
three minutes or when the offer expires, whichever comes first. The
receiver verifies the signature using a separately trusted public-key
digest and consumes the approval once under the database journal lock.
The receiver needs no Azure credentials for this check. Key provisioning
and approval delivery over the authenticated guest channel still need
integration and live validation.

Recovery tooling bundle v18 preserves an offer between authenticated guest
commands. The guest verifies the selected Azure VM instance and Linux boot
before producing or reopening the offer. It stores the recipient key in
an owner-only directory under `/run/azd-santa-recovery-recipients`, with
the operator key digest fixed at creation. Invalid approvals or mismatched
carrier files are rejected before key consumption. A successful check
writes an exclusive consumption record and removes the private key before
decryption. An interrupted attempt that reaches consumption requires
inspection of the database journal and a new offer. An unused offer
expires after ten minutes. Its private key stays local to the boot unless
the guest launcher cleans up the offer earlier.

Recovery tooling bundle v19 adds a guest command for the offer and apply
steps. It accepts a bounded canonical request on standard input and emits
one receipt. The worker supplies the journal directory, Django settings,
and database credentials locally. The command requires both Django
connections to select the verified Unix socket and configures the observer
as read-only. For a network-isolated worker, the trusted host supplies
the current VM readback as a canonical JSON file in a private, read-only mount. The command checks
that receipt against the worker's current Linux boot and selected VM.
Keep the restored PostgreSQL instance and worker isolated while using
this command. An applied stage reports whether database rows
changed and leaves application activation closed.

Recovery tooling bundle v20 stages that command in a disposable Zentral
worker using the selected local image ID. Run `restore_worker.py` on the
recovery host with the canonical request on standard input and the
reviewed tooling, commit, bundle digest and image selected explicitly.
For apply, select an owner-private workspace with `base.json`, a
`journal` directory and the isolated PostgreSQL `socket` directory.
Supply the reviewed digest of `base.json` with `--config-sha256`.
The database socket listens on the default port inside `/probe-socket`.
Use mode 0750 on the socket directory and 0770 on the socket, both in
the dedicated PostgreSQL group. The worker joins that group and mounts
the socket directory read-only. The worker has no network, no Linux
capabilities, and no application data mount. It receives only the reviewed
tooling, fresh host receipt, private recipient state, and the specific
configuration, carrier and journal needed for apply.
For preview and apply, the launcher copies the exact image's application
tree from a disposable, unstarted container into its private workspace and
mounts it read-only at `/zentral`. This gives the capability-free worker
access to the code when the image's original application directory is
private to its runtime user. The launcher removes the staging container
before preview or apply and removes the copied tree at worker exit.

Use `--docker-socket` to select the dedicated local daemon used for image
import. The launcher checks that the same socket is present throughout the
worker invocation. Keep that daemon's storage and socket separate from the
existing application daemon.

The trusted recovery host can compute the reviewed plan digest with the
worker's `--local-preview` mode. Build its private standard input with
`restore_database_command.preview_request`, using the pinned review, census
key and stage options. The preview uses the same socket, database
configuration and journal as apply. It mounts the journal read-only and
returns a plan digest without creating an offer or committing a step. Use
that digest in the subsequent offer and approval. Keep the preview input
local to the recovery host because it contains the private census key and
stage options.

When the private review and stage options are already on the recovery
VM, seal the packet there to the worker's offer and use
`restore_packet_operator.stage_local`. It verifies the selected VM and boot,
creates an exclusive private packet directory, and reads the ciphertext
back before returning the local plan and receipt. Select `--local-packet`
when signing that receipt. The same operator approval and packet integrity
checks apply, and the local receipt records no Blob upload. The Blob
delivery remains available for a packet staged on a separate sender.

The operator-side `restore_operator_approval.py` command in the reviewed
v21 tooling assembles the worker's canonical apply request. Supply the
selected store and job, the worker's offer reply, the packet transport plan
and its verified receipt. Pin the offer SHA-256, transport plan SHA-256,
reviewed database plan digest and operator public-key SHA-256 separately.
The trusted operator launcher passes the Ed25519 seed and the census key as
two consecutive 32-byte values on standard input. The command verifies the
selection, confirmation and fresh cached ARM readback, then emits the signed
request on standard output. The request contains the signed approval and
public key. Keep the local signing material in the operator process and the
request in the trusted guest transport. The command leaves transmission and
execution to the recovery workflow.

Recovery tooling v22 adds `restore_worker_transport.py` for the operator.
Its `plan` action binds the exact canonical offer or apply request, worker
image, boot, tooling and workspace. Pass the reviewed plan digest and an
owner-private workstation journal to `apply` for one bounded Run Command.
The trusted guest launcher prepares the workspace under
`/var/lib/azd-santa-qualification/restore-workspaces/<workspace>` with mode
0700, a 32-character lowercase hexadecimal workspace ID, the verified
`tooling.json` with mode 0600 and its dedicated `docker.sock`. Apply also
requires the local configuration, socket and
packet described above. The command verifies the cached Azure selection
before dispatch and after readback. The guest checks the bundle and boot,
then records an exclusive intent before invoking the isolated worker.
The workstation `observe` action reads its local journal. For an uncertain
submission, preserve both journals and inspect the guest's durable
`transport-<request SHA-256>` directory before continuing recovery.

On the recovery VM, a diagnostic run confirmed that Docker's Go-template
image inspection failed for the retained Zentral image. Docker's default
JSON inspection verified the same image ID, Linux amd64 platform and absence
of volume declarations. The isolated worker then returned a boot-bound
offer. Guest and workstation outcomes matched, and the isolated services
stopped before Azure deallocation. This offer test opened no database
connection. [Live offer evidence](https://github.com/nathanmcnulty/azd-santa/issues/53#issuecomment-7191558146)

The Azure receiver exercised signed rewrap, quarantine and administrator
reissue in an isolated workspace. Automated workspace provisioning, durable
cleanup after interruption, service-generation binding and device re-enrollment
remain open.
[Live packet transport evidence](https://github.com/nathanmcnulty/azd-santa/issues/190)

The database adapters bind the target to the Linux boot ID and postmaster
start time. A Unix-socket connection is required, and PostgreSQL must have no
TCP listen addresses. The adapters check for other client sessions across the
whole restored cluster before planning and again before commit. This requires
a dedicated PostgreSQL instance. A prior target or journal from a different
boot or from before boot binding requires inspection and a fresh review.

## Required negative, preservation and fault tests

- Captured old password, full-MFA session, pending password/MFA challenge,
  TOTP/WebAuthn assertion, reset link and invitation fail.
- Old human/service API tokens fail; a valid old OIDC assertion cannot mint a
  token row. Testing only unusable minted tokens is insufficient.
- Old superuser/group/Cedar roles cannot authorize. The fresh identity has only
  explicitly supplied authority, and old role provisioning cannot undo denial.
- Every restored device credential fails all four stages through both header
  and legacy transports, without changing inspected quota/counter/ledger state.
- Old voting/SCIM/realm sessions cannot mutate rules or memberships.
- New Monitor enrollment receives only approved new rules; restored scoped
  modes/path rules/votes are absent from its effective configuration.
- Encrypted fields and every Terraform version remain readable and semantically
  unchanged after signing rotation, including nondefault historical engines.
- All preserved business/history records remain accounted for. Stopping old
  queues is not a claim their pending jobs were safely replayed.
- Faults before commit, after commit and before generation activation never open
  a listener. Rollback never silently restores old authority. Unknown outcomes
  preserve their evidence and require explicit inspection.
- Unexpected tables/apps/store backends/engines or unreadable encrypted values
  fail closed with preserved data.
- Source checks, transaction tests and live restored-service rejection are
  separate gates; native client retry/reissue remains separate again.

This would protect the supported quarantine/reissue path. It does not make an
arbitrarily rolled-back disk or bypassed controller trustworthy. An external
current-authority boundary for automatic stale-restore detection remains a
separate unimplemented gate. No SQL, service, tenant or restore operations were
performed to prepare this design.

The [read-only restore census](restore-census.md) now supplies a bounded registry/schema/row observation and strict comparator. Controlled adapter tests are not actual Django/PostgreSQL census or full restore coverage; all authority and activation gates above remain closed.
