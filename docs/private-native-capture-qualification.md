# Private VM native capture and resume qualification

On 2026-11-15 UTC, one selected synthetic private VM completed explicit failed-request
recovery, a fresh native-snapshot encrypted capture and completion-gated resume of
its preserved original runtime. Issue54 remains open. This is one actual host case,
not an isolated restore, general recoverability claim or fault campaign.

The selected six-volume stack is `privatehook3-20261107` in the Patriot lab. Its
seven original service-container IDs, generation token and image IDs were preserved.
These are seven containers, not seven applications: complete application/schema
census remains a separate gate. Public application ingress remained denied.
Santa Monitor mode and the synthetic-only boundary were preserved. This
qualification made no Graph, Intune assignment, Mac or native-device policy change.
Private identity/credential material and raw operator fixtures are not reproduced here.

## Source and binding selection

These hashes identify the selected source/runtime bindings; they do not retain
image layers or authenticate current external authority.

| Artifact | SHA-256 / image ID |
| --- | --- |
| Runtime controller | `f0a8961f64e48471eed71757805ae4e29ee080aef30c6ab9ec040eafaf443099` |
| Cold helper | `c61618d81dc53c1d9bbfad31526757be47bd88760ff12b7683cbdb4e51c86e78` |
| Source bundle | `fcc265c25c7b07071c59d71206fa7a4fdadb00f857bdd99966d76a10fc98ecc3` |
| Local core image | `sha256:8321d09e6b0904e39e282cf07e809fdfe7c8baeb3638d77e44ba51bf4d0ce43a` |
| Runtime manifest | `0eeae6a56eb73f7751e8c3a28d68dce8888de3f65723acb916f52dbed93d640e` |
| Generation manifest | `b381ca62b0be7ff9bd5fa7c2327b38bedbf9fe0bf8902163e859b0e87c2b0066` |
| Runtime unit | `6a297da4787a8561525c62d85e746cd75221b643ff788be9d033c8272ee6078e` |

The generation manifest hash changed during the reviewed helper rebind; the
original generation token and container/image selection did not change.

## Failed operation preserved, explicit recovery completed

The original backup operation `368c81c41b584311b3e3cafe73264dd5`, request hash
`a6386505ed6f97fbb92ed78823a819627fe866835f7b9b3a3b8e94421fd38a16`,
failed before native snapshot submission. Its failed request and evidence remain
preserved. It was retired explicitly, never replayed or marked as a completed backup.

The first recovery operation `82e634d7656945f08c7eb02708089329`, using program
`379ea274ebef9247428d7dc1c53593a4e75746be04aaba6c1b8e032b3d75b2bd`
and intent `a4781fb605f036d7b24f1abbaa28f60d645a0437e253cad6ce174f518edb00eb`,
failed after disabling runtime boot start. The implicit systemd reload cleared
execution metadata and the exact historical profile guard rejected it. No request
retirement, source promotion or runtime start occurred in that failed operation;
its sixteen files and original ACTIVE/failure remained immutable.

The separately explicit disable-only continuation
`72ccdb4cba1945f8936f31d0c6faaedc` then completed. It used program
`c27dd335c6a49b7ecf9215180d9f3e7294c162e742ba86d18babdda998430e10`,
preserved the predecessor, skipped another disable, and performed one reviewed
request retirement, helper rebind and normal start. It did not request a backup.

| Continuation evidence | SHA-256 |
| --- | --- |
| Intent | `075f65b9ea5eadb4675f976fd737e5280a80e59eab17181b0f0315aa8b6c886e` |
| Completion | `580292a9ee368d112a54a65788b8e40d17b30a4b427ed267fc21cda75ed32e64` |
| Terminal proof | `52077634e8519419728e053c26b35723293a502546c4cd85d4c381ed8abc3f5e` |

See [the bounded recovery contract](presnapshot-recovery.md). Its source/fixture
checks describe the guards; the receipts above record this later actual outcome.

## Fresh capture and actual terminal observation

Fresh backup operation `3b21a864be8f44098ed120a0481835de` used request
`b55e84a32813b15c16112c26c695612f9a3385f969c3330c4c897fb2a506a521`.
The actual worker exited zero with all four current child processes joined and
exited zero. Source/current-instance-bound proof was inspected, rather than
inferring drain from queue samples or parent exit status alone.

Elasticsearch9.2.1 reported native snapshot `SUCCESS` for the observed one index
and one primary shard, zero failed shards, with global state included. The capture
used the completed native repository; raw Elasticsearch data was not admitted as
a supported backup. This qualifies that observed inventory, not unobserved future
indices or every feature-state/failure scenario.

| Capture evidence | Result / SHA-256 |
| --- | --- |
| Ciphertext length | 80,159,434 bytes |
| Archive entries reported by producer | 2,293 |
| Ciphertext SHA-256 | `1f66f3f3907f8acdd42538a493ba84b0a27d76ac3b87014bad94945008199d01` |
| Worker child-join proof | `0e992c8947d41db08728d632c89a9dda935a1afd886bfc4419b86e522d505fd0` |
| Native snapshot receipt | `b22d7d51aec17a6acba7529bf7aefea805fe17b06f82c773745b84c9e1b2bd84` |
| Caller terminal proof | `6d761415bd0d68dadfd829a95a04d5dbb28f0c9131ed64d04dcfa3583e33829b` |

A full ciphertext stream readback on the VM independently recomputed the listed
length/hash. This is same-host byte verification, not off-host retention or
independent recipient-side GCM authentication/extraction.

The transient native caller was garbage-collected by systemd: authoritative
manager readback reported `LoadState=not-found` and the exact cgroup path was
absent. The preserved source-bound ExecStopPost terminal proof recorded the
successful invocation and capture bindings. Not-found/default scalar values alone
would not prove success. An initial strict observer rejected the garbage-collected
unit case; that observation error was not a failed capture and did not authorize
resubmission. The retained terminal proof and actual readback resolved the outcome.

## Explicit resume and preservation postflight

Completion-gated resume actually passed and started the preserved original runtime.
It was resume of originals, not restoration from the ciphertext.

| Resume evidence | SHA-256 |
| --- | --- |
| Resume authorization | `fde3c360183cf7fbe5f82d2605eeb6a11fc0a19f82bf207f9c1b50bebc776b01` |
| Resume terminal proof | `1142f9e2c9714ef4cb3bd817a175b09df66ce4ac0639df583cc564ddae155cdf` |
| Preservation postflight receipt | `3d3963bcf1ce810fb8888ca1c851b1a8ca6fe839c5b30750fe9f60901de16edc` |

Before/after checks found the same seven original container IDs, generation token
and image selection. The selected database hash remained
`5c240101406dfc097b5ccc7e376881ece85c9f321c3e3d9d57b55d016d512d60`
and the selected synthetic blocked counter remained4. Seven known queues had zero
ready/unacknowledged messages. A subsequent actual Elasticsearch GET still found
the native snapshot readable and `SUCCESS` after resume. This selected preservation
postflight does not stand in for a complete database/application census.

## Remaining acceptance gates

The original ciphertext was independently read back from Azure Blob Storage
on a separate VM. See [the Azure pilot retention evidence](offhost-ciphertext-retention.md#azure-pilot-upload-and-independent-readback-2026-11-25).
The following remain separate requirements.

- Complete real schema/application census and isolated PostgreSQL/native
  Elasticsearch/full-stack restore.
- Independently trusted ciphertext receipt and complete recipient-side GCM
  authentication, safe extraction and quarantine validation.
- Portable recipient-key recovery and exact image/source/tooling retention.
- Current external authority, rollback/replay resistance and fresh administrator/
  device reissue.
- Broader interruption/crash/reboot/resource-limit qualification and native Mac,
  Intune delivery, policy enforcement and Container Apps parity.

Offline source tests, hosted CI and these actual private-host receipts establish
different facts. Neither a matching file hash, selected preservation check nor
successful resume closes the remaining restore/security gates. The
[capture contract](cold-backup.md), [restore census](restore-census.md) and
[off-host retention](offhost-ciphertext-retention.md) retain those boundaries.
