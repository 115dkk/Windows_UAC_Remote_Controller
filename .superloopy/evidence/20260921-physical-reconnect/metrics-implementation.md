# Physical-phone decision timing groundwork

Status: implemented; static source review only. This child ran no builds, tests,
formatters, lint, executable checks or device actions. ROOT/CI must validate.

## Measurement boundary

- Start: existing native approval/denial coordinator admits the local action.
  It does not include the earlier JavaScript-to-native queue delay.
- Authentication: the actual Android BiometricPrompt success callback, after the
  original Activity/CryptoObject identity and operation policy accept it.
- Local readiness: successful Android signature completion for approval; the
  existing native PREPARED denial callback for denial. Neither means PC success.
- End: existing native owner has committed the signed, verified PC terminal
  result; receipt observation happens before withdrawal callbacks/history ACK.
  NativePlatform.clock uses Android elapsedRealtimeNanos-compatible monotonic
  time, validates boot/shape and checks the existing native floor. A missing
  diagnostic clock drops measurements without affecting authorization.
- Clock boundaries remain phone-local; PC clock/ping/TCP write are not endpoints.
  This includes phone verification/commit overhead and excludes later UI paint.

## Correlation and retention

The pure PendingOutcome delivery-ID helper hashes the existing complete binding,
original issuance and fixed outcome tag. NativePendingRequest exposes only the
seven expected identities to native Kotlin; computing them asserts no outcome.
Only committed native outcomes create receipts. Receipt records contain identity,
closed outcome and monotonic observation. Registry depth is 32; duplicates retain
their first observation. Kotlin keeps at most 32 body-free local samples for at
most 300 seconds of display/measurement. It matches exact native IDs, never
history rows, request disappearance, local choice or socket-write progress.

Different local choices may have a different final PC result; presentation must
show the reported PC outcome, not assume the last tapped action was applied.
CompletedByPc remains pc_completed (legacy unspecified completion), not approval.
ExpiredLocally remains separate from PC outcomes in exported metrics.

## Projection and diagnostics

ABI 14 includes network_changed plus this lane's native records/methods.
NativeRequestCatalogStatus gains outcome_receipts. Existing version-2 request
catalog JSON gains optional/default-empty decisions, propagated through
RequestCatalogView.decisions. Fields: id (existing display locator), action,
phase, elapsedMillis, authenticationMillis, afterAuthenticationMillis. Rust
strictly rejects unknown fields, oversized/duplicate rows and inconsistent times.
This is groundwork only; no React UI is implemented by this lane.

Local state refinement: phases now include authenticating, preparing, sending,
awaiting_pc, authentication_cancelled and local_unconfirmed. The pipeline follows
existing native phases and does not enter PC wait at initial action admission.
Only the native Android authentication cancellation callback creates
authentication_cancelled; ordinary cancellation/failure creates local_unconfirmed.
Neither implies a PC cancellation or proves non-application. Local status freezes
its elapsed time but retains expected IDs; a later exact PC result supersedes it.
Fresh admission after a local terminal status starts a fresh bounded sample.

Security-review refinement: every admitted attempt carries an opaque in-process
observation token captured by local callbacks and by its retained submission.
Prepared/local-status/progress updates require that exact token; generic registry
phase changes do not mutate measurements. Historical attempts sharing outcome IDs
remain bounded at 64 for 300 seconds so replacing a visible locator cannot erase
ambiguity. History overflow conservatively excludes timing for another 300 seconds.
Ambiguous receipts still update the displayed PC outcome, but timingAvailable is
false and auth-to-receipt is omitted. Missing actual OS authentication and opposite
PC outcomes are excluded from approval-auth latency. Unique native denial samples
may retain action-to-result timing with no authentication interval.

The protocol reports the PC's shared request outcome, not the winning phone.
Even eligible intervals are local-observation spans, not proof that this phone
caused the PC result. ROOT's benchmark requires its controlled single-phone test.
Diagnostic lines now include timing_eligible; benchmark consumers must exclude
false and require actual authentication fields for approval-auth measurements.

One persisted/logcat `UAC_NATIVE_DECISION_V1` line per exact completed sample:
local ordinal, closed action/outcome and bounded action_to_receipt_ms,
action_to_auth_ms, auth_to_receipt_ms, local_ready_to_receipt_ms. Absent phases
are `none`. No request/peer/delivery identity, command, body, secret or absolute
monotonic timestamp is emitted. The diagnostic store explicitly validates the
closed line grammar and arithmetic. It uses the ordinary export path.

## Added tests (not executed)

- Pure Rust delivery identity equality and mismatched nonce/issuance/outcome.
- Rust optional/strict/bounded decision DTO and invalid duration/action/phase,
  unknown-field and duplicate-row negatives.
- Kotlin exact-match, mismatch, duplicate, backward/expired observation and
  diagnostic-sink failure cases; diagnostic persistence whitelist negatives.

## ROOT follow-up

Run formatter/build/test/lint/real Rust Analyzer gates through permitted ROOT/CI
workflow, regenerate UniFFI bindings, and update the TypeScript catalog contract.
Use an installed build with ABI14 for physical USB phone measurements. Real OS
authentication and PC application remain unverified until actual device evidence.
