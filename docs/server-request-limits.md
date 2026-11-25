# Santa request limits

The optional core image adds an original Unlicense decoder to the real pinned
Santa `BaseSyncView`. Its hash-bound layer runs after the existing credential
lifecycle guard, retains that guard and the upstream notices, and records the
helper/output hashes in `CORE_BUILD_NOTICE.txt`. No synthetic server replaces
Zentral. The default Intune-only deployment and Monitor profiles are unchanged.

The handler reads at most the compressed limit plus one byte rather than first
materializing Django's larger `request.body`. It accepts no encoding, `identity`,
zlib-wrapped `deflate`, legacy `zlib`, and `gzip`; rejects unsupported/stacked
encodings, corrupt/incomplete/trailing/concatenated streams, invalid UTF-8,
duplicate JSON members, non-finite numbers, non-object JSON and excessive depth.
All recognized event collections share a single request count budget. Empty
objects and empty event batches remain valid. Rejected input never reaches the
stage's event/rule/postflight processing; credentials are still checked by the
existing sync guard. This does not authenticate a Mac beyond those credentials.

| Runtime environment variable | Default | Hard ceiling |
| --- | ---: | ---: |
| `AZD_SANTA_MAX_COMPRESSED` | 1 MiB | 4 MiB |
| `AZD_SANTA_MAX_EXPANDED` | 4 MiB | 16 MiB |
| `AZD_SANTA_MAX_DEPTH` | 32 | 64 |
| `AZD_SANTA_MAX_EVENTS` | 100 | 1000 |

Values are positive decimal integers (bytes for the first two); invalid values
prevent startup. Lower limits can reject legitimate requests. Keep the selected
Zentral batch size at or below the event limit and separately qualify custom
limits with realistic event sizes. Oversized bodies/batches return 413, bad
encoding returns 415, and malformed JSON/compression/depth returns 400. No body,
credential, device identifier or parser exception is included in those responses.

The pinned [Santa request builder](https://github.com/northpolesec/santa/blob/dbe97b0aa0f5929feece5f4cbd2c69362c271abc/Source/santasyncservice/SNTSyncStage.mm#L106-L125)
uses zlib-wrapped deflate, gzip, or no encoding, so raw DEFLATE is deliberately
rejected. Its [event uploader](https://github.com/northpolesec/santa/blob/dbe97b0aa0f5929feece5f4cbd2c69362c271abc/Source/santasyncservice/SNTSyncEventUpload.mm#L165-L172)
batches event collections together. Pinned Zentral `models.py` sets batch size
default 50 and validates 5–100. The 100-event default accommodates that range;
it is not a native-client size/load qualification.

Offline tests exercise the decoder and generated image layer. The separate
`experiments/server/test_request_limits_live.py` gate requires the existing
loopback-only Compose and fully committed synthetic fixture. It verifies actual
helper/view hashes, sends hostile requests to all four stages, verifies five
valid empty-upload encodings, and compares the selected PostgreSQL projection
before/after. It does not initialize fixtures. Run it only during a separately
authorized live qualification; its presence or offline tests do not prove live
HTTP, native Mac, TLS, indexing or full-database behavior.

Per-request limits do not close the public-ingress gate. Before exposing a
listener, add edge compressed-byte/header/connection/time limits, bounded
upstream concurrency and a shared fail-closed request budget covering invalid
credentials and authenticated devices. Source IP must come from the trusted
proxy, never arbitrary forwarding headers. Rate keys need bounded retention and
global admission limits; credentials must be HMAC-digested before keying. Keep
this as a separate [ingress/admission change (#58)](https://github.com/nathanmcnulty/azd-santa/issues/58)
with actual overload/Redis-failure tests. Certificates, operator recovery, durable replay state, reboot readiness
and the native Mac gate remain separate work.

## Actual private HTTP acceptance, 2026-11-06

The combined image
`sha256:44c06dadff5bc3a3182eec49b4c87ed8ee256a93c6a6da62622da1ce5a088921`
passed **89 real loopback HTTP checks**: 21 hostile cases against each of four
sync stages plus five valid empty-upload encodings. Actual helper/view hashes
were checked before sending requests; the selected database projection remained
unchanged. Helper SHA-256:
`5abded58bc8a31864bfe5c116dd086fbef3f7f2738d1f87cf2d7ffab918bca1e`;
patched view SHA-256:
`205315d6cf592fe53efaebb58fb6843c4f17f842d85b7c74816964385df1ec6a`;
harness SHA-256:
`58c4a4229753540be0e15321ec22fd9184177c614cc42619854b3423fa9b11cd`;
Compose SHA-256:
`8280c8b972d698a0ce8b7d64ed7580988e894a8b8a732352b192216117125a8d`.
The private receipt is
`runtime-fixed/synthetic-fixture-backend-hardening.request-limits-9724b18a1b7d4a87a767acbf2ac2e8e3.json`.

The same image separately passed normal two-device Monitor HTTP sync, exact rule
pagination, positive event upload and committed postflight. Elasticsearch then
contained exactly ten Santa events for the retained fixture. Operator MFA and
recovery were qualified separately; see their request-suite receipts.

Earlier cold-start attempts remain retained. The first index query failed before
image transition; later diagnostics found a healthy retained index with eight
events. A later immediate HTTP gate also failed before its successful warm-runtime
run. Their generic errors do not establish an exact startup failure cause.
They do establish that the developer resume/upgrade path lacks sufficient
readiness evidence; #53 must gate event-store and listener readiness before
product admission. These successful warm-runtime checks do not prove cold-start,
load/rate, public TLS, native Mac or automatic recovery readiness.
