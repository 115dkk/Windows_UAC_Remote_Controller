<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0019: Separate SCM running from completed service initialization

Status: implementation authored; ROOT validation pending.

## Context

The service already performed platform-key work on its owned worker, but
ServiceMain retained `SERVICE_START_PENDING` until that worker finished identity,
registry and session initialization. A worker thread alone did not establish
that the provider call followed a successful SCM running report.

[NCryptOpenStorageProvider](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenstorageprovider)
warns against service-startup invocation. The
[ServiceMain guidance](https://learn.microsoft.com/en-us/windows/win32/services/service-servicemain-function)
allows long initialization after reporting `SERVICE_RUNNING` with
`dwControlsAccepted=0`, followed by a second running report accepting controls
when ready. The January17 MSFT clarification in the
[CNG startup discussion](https://learn.microsoft.com/en-gb/answers/questions/1144612/what-does-it-mean-by-cng-api-cannot-be-called-from)
recommends synchronizing worker CNG use after the SCM running report.

The retained645991e experiment exercised this ordering but still encountered
the original `0x80090030` provider failure, according to ROOT's retained result.
This decision aligns startup ordering with the guidance; it is not a TPM-error
diagnosis, remediation claim or native validation result for this source.

## Decision

Use five private reporting phases: Starting, PlatformInitializing, Ready,
Stopping and Stopped. Starting reports `SERVICE_START_PENDING` with no controls.
PlatformInitializing reports `SERVICE_RUNNING` with no controls. Only Ready
reports running with both STOP and SHUTDOWN accepted.

1. Preserve protected installation, activity-journal, service-context and trust-
   directory preflights before requesting the platform-initialization phase.
2. The worker sends one private `RunningRequest` to entry and waits on its paired
   gate. Neither value is Clone or externally constructible. The acknowledgement
   uses a capacity-one in-process channel, not IPC, a public control or a bool
   supplied by another component.
3. Entry synchronously calls SetServiceStatus. It sends success only after that
   call succeeds and original-budget/cancellation checks pass on both sides.
   The worker checks cancellation and the same deadline before and after receipt.
   Closed/failed/late acknowledgements do not release platform work.
4. The worker rechecks the original startup fence immediately before opening the
   identity. If open returns genuine KeyNotFound and the protected registry was
   absent, it checks that fence again before creation. A slow open cannot grant
   a fresh creation budget after stop or timeout. Native results are retained as
   returned; the fence does not retry or reinterpret uncertain creation.
5. Identity, registry and the existing ServiceSession must initialize before the
   original WorkerEvent::Ready. Entry reports running with readiness controls,
   then rechecks the original deadline and fresh stop state after the actual
   status call before enabling probe admission or clearing the pending deadline.
   A failed report preserves its actual error; a successful but late/cancelled
   report cannot complete local Ready. Later Progress preserves its current phase
   and can never regress an accepted SCM running report to SCM start-pending.

One startup Instant is captured before worker spawn. The original30-second
initialization budget remains active through early running until actual Ready.
Startup stop/failed-worker cleanup does not restart that budget. A subsequent
normal stop from fully Ready receives its usual shutdown budget. Control
callbacks remain bounded latches/try-send operations.

CLI/installer Start, including an already-running service, waits for running plus
both readiness controls. Running with zero or only one of those controls remains
pending. Stop/Restart/Uninstall wait through this initialization state rather
than prematurely sending STOP; existing stopped/failure/timeout results remain.
Public snapshots are a PRODUCT lifecycle projection, not a raw SCM enum: raw
SCM Running without both controls becomes product StartPending, and Running with
both becomes product Running. One central readiness predicate serves snapshots
and management waits. A nonzero PID is retained for either projection of raw
Running because SCM supplies running-process provenance. The shared snapshot
constructor is not widened: raw StartPending, Stopped and other non-running
states still discard their PIDs, and zero is always discarded.

The control mask is local bootstrap metadata, never authentication or remote
request readiness. Every remote capability remains false. No transport, listener,
pairing, approval or signing API is activated by either running report.

## Preserved boundaries and limits

- The same worker retains the current registry, engine, TLS/session and key
  ownership. No earlier experiment copies replace those implementations.
- LocalSystem, Restricted service SID, DACL/path checks, Microsoft Platform
  Crypto Provider, native flags, key policies and absence-only creation remain
  unchanged. No fallback provider, overwrite, key-creation retry or new privilege
  route is added.
- SCM running is not worker initialization success. Remote capability fields
  remain false and probe admission remains closed until actual Ready.
- An entered NCrypt call is not cancellable by this handshake. A concurrently
  arriving stop after a pre-call check cannot forcibly interrupt native work.
  No thread-kill or rollback guarantee is added.
- The post-report Ready fence cannot interrupt or retract a SetServiceStatus call
  already accepted by SCM. It prevents local probe enablement/deadline clearing
  after observed expiry/stop; it does not claim atomic SCM-status rollback.
- The normal Finished path preserves the worker error, joins an actually
  finished worker, and reports stopped with the real diagnostic outcome. Existing
  lifecycle-level timeout/report/channel-error returns still leave Worker::drop
  requesting cooperative stop; this change does not claim universal worker drain
  after every entry failure. Existing post-session staged shutdown is preserved.

## Validation

Portable private-module tests cover missing/failed/closed acknowledgements,
report ordering, stop/expiry before and during reporting, stale queued success,
phase monotonicity and unchanged deadlines/outcomes. Synthetic callbacks cover
an open that returns absence after stop/expiry, a live remaining-budget creation,
and preservation of an actual callback error without retry/rollback claims.
Windows-only pure status tests cover both accepted-control bits and real stopped
error fields, zero/one/both readiness-control projections, PID provenance and
unchanged false remote capabilities; they do not open a provider or mutate SCM.
Additional synthetic report callbacks cover Ready returning after stop/expiry,
retaining its original pending deadline and closed probes, and preservation of
an actual report error even when stop/expiry also arrives.

ROOT owns formatting, Clippy, tests, Rust Analyzer and any separately authorized
native follow-up. Source tests do not prove CNG availability or installed-service
behavior. This implementation author executed none of those checks.
