# Fresh evaluation service secrets

Fresh output from `experiments/server/prepare_zentral_eval.py` separates the
environment files consumed by PostgreSQL, RabbitMQ and the application. This is
an offline-qualified generator change, not a running-stack migration or proof
that existing containers have discarded their old environments.

| Services | Environment file | Exact keys |
| --- | --- | --- |
| `db` | `db.env` | `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` |
| `rabbitmq` | `rabbitmq.env` | `RABBITMQ_DEFAULT_USER`, `RABBITMQ_DEFAULT_PASS` |
| `web`, `workers`, `celery` | `runtime.env` | `POSTGRES_PASSWORD`, `ZENTRAL_QUEUE_URL`, `ZENTRAL_DJANGO_SECRET`, `ZENTRAL_METRICS_TOKEN`, `AZD_SANTA_SECURITY_STORE_ID` |
| `redis`, `elastic` | None | No environment file |

The application keeps the database password and broker URL it needs to connect.
The complete application configuration is loaded by all three application
services, so their five-key file is shared. It contains no broker-bootstrap
variables or unused database host/user/bootstrap-name variables. The nonsecret
configuration supplies the database name/user/host and refers to secret values
through environment placeholders. PostgreSQL and RabbitMQ receive no Django
signing key, metrics token or MFA security-store identity, and receive none of
each other's credentials.

All three environment files and Compose are created exclusively with POSIX mode
0600 within a new 0700 destination. Output cannot replace an existing directory;
failed preparation must be inspected and retried in a new destination. Secret
values are excluded from Compose, configuration and provenance. Provenance records
only the service-to-file mapping. The seven services, five named volumes,
durable Redis command and memory limits are preserved. Upstream evaluation still
defaults to its upstream app profile; a fresh core evaluation defaults to Santa,
with the existing explicit override.

`runtime.env` remains the application file used by existing private diagnostic
redaction and security-store initialization. Consumers validating a fresh stack
must accept `db.env` only for PostgreSQL and `rabbitmq.env` only for RabbitMQ;
they must inspect actual container environments before claiming that an old
shared-environment container was replaced. Editing Compose alone does not clear
an already created container's environment. No Docker or Azure operation is part
of this generator change, and it adds no secret, service, cloud role or grant.

## Database authority remains a separate gate

This change deliberately retains the same database user/password for database
initialization and application connections. Separate files reduce unrelated
secret exposure; they do not reduce that database role's authority.

At pinned Zentral source `88e67b3ce49033aab028029937a6e14f7c489073`,
`docker-entrypoint.py:129-132` runs migrations and provisioning before the normal
web/worker/Celery commands. `server/server/settings.py:182-203` supplies one
configured database credential to those operations and normal runtime queries.
A separate bootstrap/migration owner and restricted runtime role require an
explicit initialization and ownership/grant design, an entrypoint transition,
and real PostgreSQL migration/runtime validation. The isolated request harnesses
also create and drop test databases; their administrative authority must stay
separate from any future production runtime role. Renaming the current role or
merely placing its password in another file would not prove this separation.

Still unqualified: fresh image startup with these files, actual container secret
sets, separate database roles, credential rotation of existing volumes, and
restart/restore behavior after such a role change. Existing acceptance receipts
describe their original shared-environment stacks and are not evidence for this
new layout.

## Actual fresh-stack acceptance, 2026-11-06

A separate fresh Santa-profile stack with these files passed 15 real MFA cases,
13 isolated-database recovery cases, Redis interruption, full Monitor fixture
sync, 89 bounded HTTP checks and independent indexing of two Santa events.
Image:
`sha256:4533b2fdb0922ab50a8fa78d423b0613c1b5b2a843cb33244d1c8887a8804fec`;
Compose SHA-256:
`ee8ac38e730e16415d59dd5980bca03c0530135f8675846ba5d5b0ecfb6103eb`.
Private receipts are under `runtime-santa-separated/`.

The subsequent blank-human namespace passed actual host attestation of all seven
containers, including the protected environment key/value sets and independent
ports/image/source checks, before encrypted bootstrap/recovery. See
[handoff acceptance](setup-transport-slice.md) for that namespace's bindings.
The former retains its MFA fixtures and all data; its Santa state/index were
read back before explicitly pausing it. Neither result proves separate database
roles, existing-volume secret rotation, restoration or the final azd workflow.
