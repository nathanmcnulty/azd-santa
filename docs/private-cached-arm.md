# Private cached ARM capability callback

`experiments/server/private_arm_adapter.py` implements the operator-side callback
for `blob_retention.mint_capability`. It is a typed Python API without a CLI or
token export. Import, construction, `initialize()` and `mint()` are offline
plans. Only explicit `initialize(live=True)` accesses cached CLI/ARM; only explicit
`mint(apply=True)` can attempt one exact `listServiceSas` POST. No installer,
runtime, image, guest source or deployment hook changes.

Construct `Selection(tenant, subscription, store, source, verifier)` with existing
`Store`/`SelectedTarget` objects, and `CachedArm(selection, capture_record, target,
permission)`. Source permission is `c`; verifier permission is `r` and requires
the separately selected VM. `Selection.intent()` reuses the fixed existing
selector plan, checking exact typed IDs, owned subnets, region and independent
store group. The existing selector validator checks independent RG ownership,
complete tagged VM/network links, deny-all ingress, exact allowed subnets and
Storage endpoint/policy facts. It observes the complete graph twice at
initialization and again immediately before POST. Context and graph drift fail
closed; before/after reads are observations, not an atomic ARM snapshot.

Call initialization, then minting, within the same private operator process.
Pass the resulting private `Capability` directly to the existing `seal_offer`
API. Do not print, serialize, persist or put tokens/capabilities into arguments,
Run Command scripts or diagnostics. The adapter rejects pickling and has a
redacted repr; Python process memory is not protected against its trusted caller,
debugger, crash dump or a compromised host. Capture authenticity and current
operator authority remain independent prerequisites; no receipt authenticates
caller-supplied capture facts.

The cached CLI commands are restricted to `version`, `account show` for the
explicit subscription, and `account get-access-token --subscription <id>
--resource https://management.azure.com/`. There is no login, account switch,
device-code, grant, role/policy/provider change, key retrieval or fallback.
Commercial Azure, Enabled subscription, matching tenant/subscription and a cached
user/service-principal profile are required. Managed identity and Cloud Shell
profiles are rejected. Token tenant/subscription/type and UTC `expires_on` must
match and outlive the bounded attempt. Context is checked before/after token
acquisition, around graph readbacks and after POST. The token is private memory
only and cleared from the adapter on terminal success/failure; immutable Python
strings cannot be securely erased.

The supported CLI contract is version 2.x >=2.54.0, when UTC POSIX `expires_on`
was introduced. See the official [account command reference](https://learn.microsoft.com/en-us/cli/azure/account?view=azure-cli-latest)
and [authentication reference](https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli?view=azure-cli-latest).
Although both switches are documented, the CLI profile implementation rejects
simultaneous subscription and tenant: [get_raw_token](https://github.com/Azure/azure-cli/blob/dev/src/azure-cli-core/azure/cli/core/_profile.py).
The adapter therefore supplies subscription only and checks returned tenant.
CLI configuration disables file logging, telemetry, dynamic extension install
and automatic upgrade for these subprocesses, following the documented
[environment/configuration precedence](https://learn.microsoft.com/en-us/cli/azure/azure-cli-configuration?view=azure-cli-latest).
The trusted installed CLI/MSAL may refresh its existing cache; this is not a
promise to suppress every internal SDK retry or prevent normal CLI cache writes.

Live initialization resolves the trusted installed application with
`shutil.which('az')` once, requires an absolute regular application path and pins
its path/device/inode/size/mtime for subsequent commands. Significant batch-shell
metacharacters in the path reject. Windows accepts only `az.cmd`/`az.exe` and
explicitly quotes the full launcher path: bare `az` with `shell=False` does not
resolve a batch launcher reliably. This stability pin is not binary attestation;
trusted operator installation, PATH, environment and OS remain external gates.

CLI stdout is bounded to 64 KiB while reading, stdin/stderr are discarded, and
each process has a maximum 30-second wait with process-tree termination on
failure/timeout. Windows process-tree termination uses the absolute system
`taskkill.exe`, independent of PATH. Arguments contain only fixed verbs/flags and
validated GUIDs; the Windows batch command is built from that restricted vector
and the quoted trusted launcher path. No secret is passed in argv. Direct TLS uses the system trust store and fixed
`management.azure.com:443`, bypassing environment proxies. There are no HTTP
redirects, application retries or raw response/error diagnostics. Only exact
versioned graph GET URLs and the exact selected-account SAS POST are accepted.
The POST body must bind the exact blob, `b`, `https`, selected `c`/`r` permission
and canonical 30-minute signing window with at most 15 minutes remaining.

Attempts have a 1–300 second overall monotonic deadline (default 180), 96 GET
limit, 256 KiB per JSON response and 32 MiB aggregate GET response limit. TLS
connect/read waits are capped at 15 seconds or remaining time; read1 chunks
recheck the deadline and a socket-shutdown watchdog interrupts slow-drip
header/body waits at the absolute deadline. Duplicate keys, non-object JSON, compression, non-200
status and oversized/truncated responses reject. OS process startup, DNS resolver
and installed CLI internals remain trusted execution prerequisites: socket
timeouts cannot preempt a stalled OS resolver. A deadline check after connect
prevents dispatch following a late connection. External orchestration should
also bound the private operator process; a timeout is never permission to replay.

Concurrent callbacks are rejected. The adapter fences the POST before dispatch;
success, lost response, malformed response, context drift and timeout all close
the attempt. There is no retry/reinitialize/resume path. This in-memory fence
does not provide durable cross-process mint deduplication. The guest relay's
one-use journal is a separate boundary. A restart requires independent operator
reconciliation and must not silently recreate an attempt after unknown outcome.

Offline tests use controlled CLI/HTTPS adapters and synthetic selected resources,
including real existing capability validation. They do not prove cached token
acquisition, actual ARM API/RBAC sufficiency, Storage minting, guest delivery,
Blob retention, separate verifier download, lifecycle survival or restore.
End-to-end cached ARM/Run Command orchestration and durable operator attempt
observation remain unimplemented integration gates. No cloud/guest/auth calls
were performed for this change; existing source Linux relay qualification is
separate evidence. No acceptance or permission grant is inferred.

The focused 23-case suite also launches a real owned temporary fake `az.cmd`
(or POSIX `az`) under a restricted PATH using the existing interpreter. It checks
fixed argv, changed-launcher rejection and actual fixture-child termination on
timeout; it never invokes the installed Azure CLI. HTTP slow-header interruption
uses controlled SSL/socket/clock/timer adapters with positive header-wait entry,
deadline registration, shutdown and cancellation assertions. A separate case
proves expiry during SSL setup rejects before connection/request/watchdog.
The earlier 50 ms wall-clock test could expire during hosted Windows CA loading;
such safe early rejection does not exercise the intended watchdog phase. No
network or real TLS is exercised by these cases. PowerShell 7.6.9/Pester 6.2.0
full suite passed 302 tests, 1 skipped, 0 failed before the final launcher and
watchdog adjustments; the final focused callback, evidence and permission-schema
checks passed afterward. Actual CLI/cache/API/TLS compatibility remains a
separate integration gate.
