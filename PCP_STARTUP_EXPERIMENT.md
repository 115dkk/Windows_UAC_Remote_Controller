# PCP startup-order experiment — source receipt

2026-09-10; isolated branch `codex/pcp-startup-phase-probe`, base `7b9df1f`.
Diagnostic hypothesis only; not a confirmed cause or a main-branch promotion.

## Discriminator

Root supplied the native baseline: the service's first platform-provider open
failed at `NCryptOpenStorageProvider(MS_PLATFORM_CRYPTO_PROVIDER, 0)`; SCM
`0xE6070030` preserves operation 7 and original HRESULT `0x80090030`. The same
provider opened/closed in a medium-user comparison. This worker did not reproduce
those observations.

The experiment keeps protected installation, journal, service-context and trust
directory preflights, then waits before the first `PcIdentityKey` open/create.
The entry thread reports `SERVICE_RUNNING` with no accepted controls. A private,
consumed-once channel acknowledges only after that exact synchronous report
returns successfully; entry and worker check cancellation and the same original
30-second startup budget. Failed/disconnected/late/cancelled acknowledgement
does not release platform initialization. No retry or provider fallback exists.

Later Progress retains Running/no-controls. Only the original Ready event,
after identity, registry and `ServiceSession` initialization, advertises
STOP|SHUTDOWN and enables the existing probe admission. CLI Start requires both
control bits in addition to Running; Stop/Restart/Uninstall wait through the
no-controls phase within the existing command deadline. Those bits indicate
bootstrap completion only, never authentication or remote approval readiness.

## Scope and retained invariants

- Changed `runtime.rs`, `entry.rs`, `native.rs`; one safe `startup_phase.rs` helper
  and minimal `lib.rs` module wiring. No identity, provider, key policy, flags,
  LocalSystem, restricted SID, ACL, installation or authorization changes.
- No listener, IPC command, remote-ready claim, observation probe on startup,
  software key fallback or retry after uncertain creation.
- Original worker/session drain and identity-close path remains in place. Entry
  still requires actual Finished plus thread exit/join before reporting Stopped;
  a status failure or deadline error is not a fabricated cleanup success. No
  unsafe thread termination or extended startup budget was added.
- Stop callbacks remain bounded. Worker acknowledgement checks also observe the
  existing process-lifetime stop latch. Startup cancellation does not grant a
  new startup/cleanup budget.

## Evidence status

Source-authored tests cover pre-ack denial; successful-report ordering; failed,
closed, late and cancelled acknowledgement; phase transitions; real-ready-only
controls; no StartPending regression; worker failure preservation; startup
cleanup deadline; and CLI Running/no-controls rejection. Windows-specific tests
construct status records only and do not call SCM.

No builds, tests, formatting, lint, Rust Analyzer, CI, service/UAC execution,
installation, OS/security setting changes, commits or pushes were performed by
this worker. Root must run all validation. These channel/policy tests are not
proof that Windows PCP succeeds, native cleanup completes, or remote UAC/phone
authentication works. A hung native CNG call is not forcibly interrupted; the
entry startup deadline remains a failure, not Ready or cleanup success.

## Primary-source rationale (retrieved 2026-09-10)

[Microsoft ServiceMain guidance](https://learn.microsoft.com/en-us/windows/win32/services/service-servicemain-function)
permits reporting Running without accepted controls during long initialization,
then advertising controls once initialized. The
[Microsoft Q&A January 17 clarification](https://learn.microsoft.com/en-gb/answers/questions/1144612/what-does-it-mean-by-cng-api-cannot-be-called-from)
supports synchronizing CNG work after Running is returned to SCM. This motivates
the discriminator; neither source proves the observed HRESULT's cause.
