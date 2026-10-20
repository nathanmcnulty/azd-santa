# Offline-safe Live Response resumption

`Invoke-SantaLiveResponseHealth.ps1` keeps the existing schema 1.0 success
artifact at `ResultPath`. A separate schema 1.0 action receipt defaults to
`<ResultPath>.action.json` (override with `ReceiptPath`). Both paths are private
operator evidence, not material for issues or pull requests. The receipt contains
only the selected tenant/account, machine identity, script, action ID, status and
timestamp; it excludes output, credentials and download URLs. Receipt files are
owner-only on Unix and protected to the current user on Windows.

The receipt is written before submission as `submission-uncertain`, then updated
with the returned action ID immediately after submission and before the first
poll. A submission error or missing ID is **not** permission to retry the POST.
Recover the existing action ID through an authorized read-only investigation,
then resume using `-ExistingActionId` and the same target, account, script and
paths. An existing receipt blocks a fresh submission. A receipt with a known ID
rejects a different ID; an uncertain receipt without an ID can bind the recovered
ID. Each visible action row must match that ID and the exact machine before its
status is interpreted. Verified completion also requires a LiveResponse action,
a RunScript command for the selected ScriptName, and a transcript with matching
script_name. No automatic POST retry occurs. Invocations sharing a receipt are serialized
using a persistent, empty `.lock` file; a stopped process releases the lock.
Do not choose a new receipt path to bypass an uncertain submission.

Receipt states:

- `submitted`, `not-yet-visible`, `pending`: polling is still underway.
- `polling-timeout`: the bounded window expired; this is an unverified outcome,
  not action failure. The runner returns a `state`/`receiptPath` object and warns
  to resume. It does not create success evidence.
- `polling-error`: polling could not continue; retain the ID and resume.
- `binding-mismatch`: the returned action does not match the selected target.
- `action-failed`: the service explicitly reported Failed, Cancelled or Rejected.
- `action-timeout`: the service explicitly reported TimeOut; this is distinct
  from an expired local polling window.
- `command-failed`: explicit command failure or a failing script result.
- `command-unverified`, `result-unverified`: no verified completion evidence yet.
- `verified-completion`: command completion and successful script output were
  verified. The original success artifact contract remains unchanged.

A prior success file is not deleted on a later run. Consumers must match its
`action.id` to the current receipt and require `verified-completion`; file
existence alone is not evidence that the current action passed.

The profile diagnostic consumes full grep input under `pipefail`, emits only
summary fields, and reports failed profile commands as unknown. Its offline
regression uses a mocked profiles function and large early-match inventories:

```bash
bash tests/Test-SantaProfileState.sh
```

The regression runs in the existing Linux and macOS validation jobs; no extra
hosted macOS jobs or live service tests are added. The PowerShell regression uses
mocked HTTP clients and Azure CLI responses only. Live endpoint validation is
separate and remains outside this change.
