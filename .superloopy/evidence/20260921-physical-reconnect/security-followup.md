# Security follow-up: native phase ownership and measurement APK

Date: 2026-09-21. Independent static review of uncommitted changes against
`3c3d4e60ba41bf4feacce3a7d8d13b0f8435a21e`. Reviewer owns this report only;
no product edits, child delegation, validation commands or device actions.
ROOT/CI remains responsible for executable gates and actual authentication.

## Review result

The settled workflow, network correction and finalized native phase-owner fix
have no unresolved new high/medium security/correctness finding from this static
review. The writer handed off the final M3 files; ROOT's staged product/workflow
files match the reviewed working-tree versions. M3 is now fixed at source level,
superseding its deferred disposition in `security-review.md`.
The APK workflow produces a measurement candidate, not a release or proof that
quality gates, phone authentication or Windows application passed.

## One-off APK workflow

Reviewed `.github/workflows/android-physical-measurement.yml` and the passive
APK-inspection helper it invokes. Findings raised to ROOT and corrected:

- Originally `workflow_dispatch` bypassed the branch/actor restriction. The
  global condition now requires the repository-owner actor; dispatch is limited
  to `refs/heads/codex/decision-feedback-research`. PR runs require that exact
  branch in the same repository, and the PR trigger filters only this workflow
  file. Fork/arbitrary-head execution cannot take this signing lane.
- `umask 077` now precedes decoding the persistent signing keystore. Its exact
  runner-temporary path is removed by the exit trap and is not an artifact.

Other source observations:

- Actions are commit-pinned. Job permissions are `contents: read`; checkout
  disables credential persistence. No release, tag, PR write or publication API
  occurs in this workflow.
- Checkout selects the actual PR head SHA (or dispatch SHA), and the build step
  compares `git rev-parse HEAD` to `SOURCE_SHA`. Artifact naming and
  `product-commit.txt` retain that SHA; the APK checksum is recorded separately.
- This is owner-authored same-repository code. Repository build scripts run
  before signing in the same job; the branch/actor trust gate is essential, not
  optional. This would not be a safe general untrusted-PR signing workflow.
- Persistent signing inputs are required; there is no ephemeral-key fallback.
  Passwords are passed through named environment variables, not command text.
  No `set -x`, secret echo or secret-bearing output artifact is introduced.
- `apksigner verify --print-certs` must produce the tracked expected SHA-256
  certificate digest; missing/malformed/mismatched identity fails the job.
  The public certificate metadata is not the private signing key.
- Only `measurement-out/` is uploaded, after all preceding steps succeed. It
  contains the signed APK, public certificate information, passive APK/manifest
  inspection, product commit and checksum. No key, password, bootstrap QR or
  device diagnostics is intentionally included. Retention is 14 days.
- APK inspection checks the expected arm64 library layout; boot-manifest
  inspection remains present. Neither inspection executes the phone app or
  establishes per-use authentication. ROOT must check the downloaded artifact's
  signer/hash/source and install it as an in-place update without erasing keys.

## `run_dial` correction

`connectivity.rs` now exposes an explicit `impl Future<Output = DialCompletion>
+ Send` contract. It wraps only the rendezvous wait in the locked tokio-util
0.7.19 `run_until_cancelled_owned`, then performs synchronous stream admission.
No lint/Analyzer suppression, unsafe Send/Sync implementation, trust-pin change
or clock/deadline relaxation is introduced.

The [versioned CancellationToken API](https://docs.rs/tokio-util/0.7.19/tokio_util/sync/struct.CancellationToken.html#method.run_until_cancelled_owned)
documents that an already-cancelled token returns no result; cancellation drops
the pending future, while simultaneous completion may win. The implementation
retains the decisive cancellation check inside `attach_network_stream` after
exclusive native owner admission. A carrier returned in the simultaneous case
therefore cannot attach after `network_changed` has cancelled its generation.
Generation-tagged completion and existing bounded retry rules remain intact.

The reported Rust Analyzer error and its resolution remain ROOT's exact-commit
CI responsibility. This source review neither reproduces the diagnostic nor
claims the new code compiles or that a physical reconnection succeeds.

## M3 native action-generation ownership

The new `NativeActionGeneration` / `NativeActionPhaseOwner` is distinct from the
optional `NativeDecisionObservation`. Existing native coordinators still decide
whether approval or denial is admitted; phase ownership is installed only after
their real admission result. Diagnostic presence and timing eligibility do not
grant action ownership or alter authentication.

`Registry.phase` and `keepDelivery` require the current native generation. The
retained delivery carries its generation to later progress callbacks. Stale
terminal callbacks cannot clear a newer generation; retirement cannot be
reopened. Entry replacement transfers ownership only for the retained current
delivery, not an arbitrary old callback. Actual Rust request/signing/denial
checks and the exact-request denial drain remain in place.

The per-entry `actionAdmissionLock` serializes the bounded native request/enqueue
call and generation publication, which otherwise run on main for approval and
the single owner worker for denial. Its two acquisition sites are outside
registry/entry locks. Phase callbacks never acquire this admission lock. Native
cryptography, disk access, OS prompt lifetime and waiting for worker completion
are not performed under it. Registry entry updates use their existing lock order.

Callback-before-publication analysis uses the actual production schedulers:

- Approval admission occurs on main. Worker results are delivered through
  `ApplicationApprovalCoordinator.deliver` via main posting, so cannot overtake
  the currently running main-thread admission block.
- Denial admission occurs on the same single worker used by `DenialJobs`.
  Successful `WAITING` admission installs/enqueues its job without a synchronous
  callback. That job cannot execute until the admission task has published its
  generation and returned. Rejection callbacks belong to unadmitted generations.
- A prior-generation callback during admission either executes before the new
  initial phase (which then supersedes it), or after publication (and is rejected).

These are important scheduler assumptions, not an abstract guarantee for an
arbitrary injected callback/executor. Tests of the pure generation owner are
useful but do not independently exercise Android main/worker ordering. ROOT/CI
must preserve these production scheduling rules and validate the changed native
callback paths, including stale approval cancellation during denial, rejected
admission, retirement, replacement and retained submission progress.

Final M3 disposition: the eight pure owner tests include synchronous unadmitted
callback rejection, old callbacks before/after new-generation publication,
stale cleanup, retries, retirement and replacement. Their source was inspected;
no test was executed by this reviewer. No duplicate callback-resource buffer
was added, so Prepared submission cleanup retains one existing owner.

## Retained delivery and the exact denial boundary

ROOT additionally checked that `deliveries()` may still return an earlier
retained submission after a newer denial owns the displayed phase, and that
`advanceDeliveries` invokes `requestApprovalDelivery` before the presentation
phase check. This is deliberately not turned into a presentation-based
authorization gate; the behavior predates M3.

The authoritative boundary is Rust `reserve_denial`, which retains the
request-scoped fence before `cancel_request`. `request_approval_delivery` checks
controller ownership, cancellation and `denial_fence`; `process_delivery`
rechecks the fence before taking the core and after queueing. The existing
cancellation/transport ownership handles pending work. No M3 edit removes these
checks or introduces a new send path.

Kotlin `WAITING` is only bounded denial-job admission. Before that job actually
executes Rust reservation, an earlier queued/sent approval may already win;
already transmitted decisions cannot be retroactively withdrawn. Therefore the
report does not claim that Kotlin denial admission unconditionally cancels an
earlier signed decision. The UI must continue to distinguish the latest local
choice from the PC's actual request outcome. This pre-existing boundary is not
expanded or weakened by the phase-ownership fix.

## Release/measurement gate disposition

ROOT can push this coherent candidate and run the restricted same-signer APK
workflow. Full exact-commit CI, Rust Analyzer, negative protocol controls, APK
artifact verification and real-phone tests remain pending evidence. The
restricted build does not replace release gates or publish a prerelease. A
valid authentication benchmark still requires the controlled single-phone
canary, actual OS-authentication/signature observations, matching PC diagnostics
and process result; ping or an APK build cannot supply that result.
