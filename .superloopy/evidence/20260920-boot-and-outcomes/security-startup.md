# Startup-observer static security audit

Date: 2026-09-20. Reviewer: security_review (independent child).
Reviewed state: uncommitted startup-observer delta over `2926af0`, including
ROOT's follow-up pre-publication and final-completion startup-budget fences.

## Verdict

**PASS for the bounded startup security slice.** No remaining authority or
fail-open finding in the reviewed changes. The initial deadline finding below
was corrected by ROOT and its source was re-read. This is not a claim that the
reported physical cold-boot failure has been reproduced or cured.

Scope: `native.rs`, `startup_phase.rs`, `runtime.rs`, `ffi/mod.rs`,
`ffi/process_observer.rs`, `ffi/process_observer/diagnostics.rs`, and
`tools/service-startup-diagnostic.psm1`. Android history/UI work is outside this
audit. No builds, tests, formatting, lint, native checks, service operations or
child delegation were performed; only this receipt was written.

## Evidence and causal limit

ROOT supplied the alpha.38 failure observation: `2026-09-20T02:16:42Z`, PID 5916,
stage 7, phase `scm`, category `configuration`, numeric code 0, policy 0. Manual
restart works; the presently observed registration and service SID are normal.
The old `scm` phase combined registration/configuration/security validation with
status/self-PID validation. Thus it proves failure before ACL publication but
does **not** prove that a stale StartPending observation was the failing condition.
Presently normal configuration also does not establish its exact earlier state.

The change is supportable as a narrow, fail-closed timing compatibility correction
and diagnostic split. Its specific causal hypothesis remains unverified until
ROOT/native evidence identifies the transient state or repeated physical reboot
acceptance demonstrates the actual installed behavior. Ordinary CI startup and
pure convergence tests cannot replace that physical reboot evidence.

## Invariants checked

- `registered_service_for_probe` retains exact protected registration, service
  security and unrestricted own service-SID checks. Its name/returned handle grant
  no process/ACL/key authority. The only new weaker-status caller is the internal
  observer-startup path (`native.rs:160`, `ffi/process_observer.rs:233`).
- All ordinary probe/peer paths still call `running_service_for_probe`; it invokes
  the same registration checks and requires observed Running with this exact
  process ID. No client-facing API, new command, caller PID/path, privilege or
  service configuration mutation was added (`native.rs:145`).
- Runtime enters observer provisioning only after the existing one-use in-process
  Running/no-controls acknowledgement. Observation polling permits only
  StartPending with no accepted controls to continue waiting. A subsequent ROOT
  delta also waits on Running with an unpublished PID (None/zero), without granting
  any process authority. Stopped, stopping, paused/other states, accepted controls,
  or a nonzero wrong Running PID are terminal. Only exact Running/self PID admits
  later work; a missing/pending PID is never adopted (`ffi/process_observer.rs`).
- Query failures are terminal, not retried. Polling checks stop and the original
  startup deadline before and after each observation; sleeps are at most 25 ms
  and no greater than remaining budget. Late success fails. No fresh 30-second
  allowance, repeated SetServiceStatus, ACL retry, recovery loop or restart was
  introduced (`startup_phase.rs:19,27`). Native query calls remain synchronous;
  this does not assert that an entered Windows call is forcibly cancellable.
- Once convergence succeeds, original strict startup/context/image/SCM checks
  run again. Existing token, exact descriptor drift, DACL-only publication,
  unchanged owner/group/MIC/SACL scope and exact readback checks remain in place.
  No unsupported policy is repaired or relaxed.
- ROOT's added `run_platform_step` immediately before SetSecurityInfo rejects an
  observed exhausted original budget or stop before entering the mutation. The
  final fence after strict readback/startup recheck rejects late completion before
  success can reach subsequent key/readiness work
  (`ffi/process_observer.rs:310,351`). Neither fence retries or rolls back a native
  operation already entered.
- Diagnostic additions are four fixed literals: `scm_status`, `scm_state`,
  `scm_process`, `scm_controls`. Production record size/count, numeric-only cause,
  closed parsing and no-SID/no-path/no-ACL/no-prompt boundaries are unchanged.

## Finding and regression coverage

| Severity | Finding | Disposition |
| --- | --- | --- |
| Medium, corrected | A successful observation near the original 30-second deadline could be followed by slower existing preflight calls and a new SetSecurityInfo invocation after expiry; the initial patch fenced only the wait, not the subsequent publication. | ROOT added the existing startup fence before the actual SetSecurityInfo call and after final strict readback/startup checks. Source inspected; closed for static review. |
| Low, coverage, corrected | The diagnostic parser's existing accepted fixture only exercised `merge`, not the four added phase values. | ROOT added positive fixtures for scm_status/scm_state/scm_process/scm_controls; source inspected. Enum/allowlist equality was checked statically. |

New test sources cover pending-to-ready convergence, no retry on error, late
success, exhausted budget, cancellation before/after observation, wrong PID and
unexpected controls/states. Existing `run_platform_step` tests cover expired or
cancelled preissue rejection. These checks were authored/read, not executed by
this reviewer. ROOT owns exact-commit CI and actual installed/native evidence.
