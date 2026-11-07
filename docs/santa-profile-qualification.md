# Fresh Santa-only profile qualification

Developer qualification only. No product deployment, customer migration,
automatic service transition or resource-saving claim is made here. The default
upstream evaluation profile remains unchanged.

Fresh core preparation now defaults to the qualified Santa-only profile. An
explicit `--app-profile upstream` remains available for controlled comparisons;
this generator never updates an existing runtime or database in place.

The generator's `santa` app profile omits Jamf, Munki, osquery and Turbo while
retaining the eight automatically enabled core/inventory/admin apps plus Santa.
PostgreSQL, Redis, RabbitMQ, Elasticsearch, web, workers and Celery remain; real
event storage/search and the incident pipeline must not be traded away merely
to produce a smaller-looking configuration.

`qualify_santa_profile.py prepare` reuses the existing generator with explicit
previous Compose, private fixture, project name, immutable image and pinned
source inputs. It creates an absent separate directory, new random Compose
project and project-scoped volumes, with exactly the prior dependency/application
images. Its private plan binds the old/new hashes and labels every runtime gate
`not_run`. Preparation neither contacts Docker nor pauses anything. Matching
project identity is not authorization to stop it.

Before any actual VM qualification, inspect the plan, establish that its new
Docker namespace/volumes do not already exist, verify the built image/source,
read the old synthetic database receipt, and separately authorize pausing the
**exact selected old project**. Both profiles bind loopback port 8000 and a small
VM must not be assumed able to run two complete stacks. Retain old project/data
volumes; do not use `down --volumes`, prune, or silently recreate another project.

During that separately authorized qualification, reuse the existing startup,
readiness and private test helpers rather than introducing another orchestrator:

1. Start only the fresh selected namespace. Run actual checks, migrations and
   provisioning. Inspect required provisioner imports and process exit codes;
   an upstream zero exit alone has previously hidden store-save failures.
2. Run `qualify_santa_profile.py check-runtime --plan <private-plan>` **before
   creating fixtures or operators**. This readonly app/DB projection requires
   exactly nine configured and installed apps, their applied migrations, no
   optional-app migration records, no human/configuration/device rows, and one
   provisioned Elasticsearch admin store. It does not prove complete DB
   emptiness or Docker namespace freshness by itself.
3. Verify stable worker processes and actual consumers for the Elasticsearch
   store, enrich/process pipeline and Celery. Keep real Redis security semantics.
   Where the selected generator enables durable Redis, retain its project-local
   Redis volume and complete its separate explicit marker/durability
   initialization gate; preparation never initializes or flushes security state.
4. Run the selected MFA and isolated-database recovery request harnesses. The
   recovery first-admin case now renders the real empty Santa index after normal
   password/TOTP/MFA authentication. Its count stays unchanged; the harness hash
   changes. This is direct Django request evidence, not a browser/TLS receipt.
5. Initialize a **new** synthetic fixture in the new project. Run complete
   loopback preflight, pagination, positive events and postflight; verify the
   actual DB receipts, required Elasticsearch event count and admin search.
   Reuse the bounded-request HTTP gate. Preserve source/hash-bound receipts.
6. Measure actual resource use and retain limits, logs and failure evidence.
   Optional app removal alone proves neither RAM savings nor production sizing.

Every step needs its own actual receipt before adopting the profile. Do not
reinterpret `not_run` plan fields as completed gates. A failure leaves the new
experiment for inspection, without automatic rollback, deletion or old-project
resume. Any deliberate resume must select the previous exact Compose/fixture/
image explicitly through the existing guarded developer flow.
