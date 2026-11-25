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
Use `-Resume -Apply` with the same target, account, script and paths when the
receipt has a saved ID. If the submission outcome is uncertain and the ID is
missing, recover the ID through an authorized read-only investigation and use
`-ExistingActionId -Apply`. An existing receipt blocks a fresh submission and
rejects a different ID when the ID is known. Each visible action row must match
that ID and the exact machine before its
status is interpreted. Verified completion also requires a LiveResponse action,
a RunScript command for the selected ScriptName, and a transcript with matching
script_name. No automatic POST retry occurs. Invocations sharing a receipt are serialized
using a persistent, empty `.lock` file; a stopped process releases the lock.
Do not choose a new receipt path to bypass an uncertain submission.

`azd` postprovision uses `-ReuseReceipt` with the environment's existing paths.
The first run can submit an action. A later run with a saved action ID resumes
polling, and an already verified result is reused after checking its SHA-256.
Reusing a completed result makes no Defender request and preserves its capture
time. If submission was uncertain and the ID is missing, recover the action ID
before resuming. A later deployment never retries that submission.

Receipt states:

- `submitted`, `observing`, `not-yet-visible`, `pending`: polling is still underway.
- `polling-timeout`: the bounded window expired; this is an unverified outcome,
  not action failure. The runner returns a `state`/`receiptPath` object and warns
  to resume. It retains the last recognized service status without storing
  unknown response values. It does not create success evidence.
- `polling-error`: polling could not continue; retain the ID and resume.
- `binding-mismatch`: the returned action does not match the selected target.
- `action-failed`: the service explicitly reported Failed, Cancelled or Rejected.
- `action-timeout`: the service explicitly reported TimeOut; this is distinct
  from an expired local polling window.
- `command-failed`: explicit command failure or a failing script result.
- `command-unverified`, `result-unverified`: no verified completion evidence yet.
- `verified-completion`: command completion and successful script output were
  verified. The receipt records the hash of the existing schema 1.0 result.

Resume preserves terminal receipts and their results without issuing another
Defender request.

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
