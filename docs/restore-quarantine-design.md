# Restore quarantine and fresh-authority reissue design

**Design only; unimplemented and unqualified.** This is the bounded inventory
and proposed workflow for [issue54](https://github.com/nathanmcnulty/azd-santa/issues/54).
It does not enable restore, qualify full restoration, or establish an external
current-authority ledger. Cold encrypted backup acceptance is a separate gate.

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

## Signing rotation and secret recoverability

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

The customer goal is a guided command with explicit selected backup and current
authorization, not hand-built administrator JSON or a chain of manual SQL
commands. The design does not yet supply that command or its crash protocol.

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
