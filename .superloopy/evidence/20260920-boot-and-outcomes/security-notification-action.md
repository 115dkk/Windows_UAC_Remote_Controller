# Notification-action security/lifecycle review

Date: 2026-09-20. Reviewer: security_review. Scope: existing alpha.38 Android
notification approve/deny routes versus in-app actions. Initial method: static
source inspection. ROOT subsequently authorized the narrow Kotlin fixes described
below. No validators, device commands or child agents were used.

Kotlin paths below are relative to
`src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/`.

## Verdict and physical evidence limit

**Findings: request-local error escalation and lost failure classification;
both addressed in source by the authorized implementation follow-up below.**
The source contains a concrete path by which a recoverable presentation-refresh
failure in one action stops the shared native actor and its connectivity. It is
a credible candidate for the reported symptom, not a proven reconstruction of
the user's specific tap. No authorization bypass was found in the inspected
notification routing. This is not blanket approval of all request actions.

ROOT reports the user-authorized phone is presently PID 22162, owner READY, with
only earlier activation/start-admission messages surviving the bounded log read.
The exact exception from the failed notification action is unobserved. This
reviewer did not access the device. No approval/authentication/reboot test should
be inferred from this report, and none was initiated while the user was asleep.

## Route comparison

| Route | Entry | Shared owner and authority |
| --- | --- | --- |
| Notification approve | Immutable explicit one-shot Activity PendingIntent -> MainActivity onCreate/onNewIntent -> ControllerApplication pending route -> actual foreground resume | Original process-local registry locator/key, live Rust handle recheck, ApplicationApprovalCoordinator, request-bound native authentication/signing |
| Notification deny | Immutable explicit one-shot broadcast -> nonexported ControllerRequestActionReceiver -> existing Application actor, no Activity | Original registry locator/key, live Rust handle recheck, DenialJobs with original request scope and separate denial signing purpose |
| In-app action | Captured current Activity/WebView command adapter -> ControllerApplication | Same NativeRequestCoordinator and approval/denial owners; no notification one-shot selector consumption |

References: `background/NativeRequestRegistry.kt:535`, `MainActivity.kt:45,58`,
`ControllerApplication.kt:272,283,290`,
`background/ControllerRequestActionReceiver.kt:14`,
`background/NativeRequestCoordinator.kt:165`.

Notification extras are not accepted as authority. URI shape and full key/locator
are bounded; a route must match the existing entry and original native handle.
Restored/cold Activity state cannot invent an approval plan. Approve still needs
the actual current foreground host and OS authentication; deny does not launch
an authentication Activity. The broadcast's eight-second `goAsync` completion is
not claimed as delivery or cleanup, and an accepted actor job remains retained.

## F1 — Medium: request-local refresh is escalated to shared-owner failure

`background/ApplicationApprovalCoordinator.kt:313,493` handles exceptions from
the action worker by cancelling the exact session, then considers almost every
BridgeException fatal. It excludes ApprovalRejected, Busy, InvalidPolicy and
HistoryTimeUnavailable, but not PresentationRefreshRequired or RequestUnavailable.
The same predicate is also used at cleanup (`:391,397`), so request-operation and
cleanup uncertainty are currently conflated.

`background/DenialJob.kt:195,205` catches Busy and DenialRejected specially, then
its general Throwable branch cancels the job, marks cleanup failed and calls
`ownerFailed()` unconditionally. A typed presentation-refresh signal therefore
retires all requests rather than just the affected attempt.

This is more than a theoretical enum mismatch. Rust can propagate the existing
normal `PresentationRefreshRequired` signal through:

- `crates/android-bindings/src/approval.rs` `run_approval` ->
  `dispatch_approval_checks` -> `dispatch_effects`;
- `crates/android-bindings/src/denial.rs:794` `check_denial_bound` ->
  `dispatch_approval_checks`;
- `crates/android-bindings/src/effects.rs:298` returns that refresh signal from a
  presentation publication without treating it as authorization success.

The native clock explicitly distinguishes refresh-needed sampling/time-zone
invalidation from a fault (`background/NativePresentationClockSource.kt:87`).
Maintenance already catches PresentationRefreshRequired without killing the
actor (`background/NativeRequestCoordinator.kt:69`).

By contrast, the action callbacks at `background/ApplicationPolicyActor.kt:69`
invoke `failOwner`; `:600` stops request maintenance, denial and approval owners,
fails lifecycle state and begins owner cleanup. `ControllerApplication.kt:524`
then projects UNAVAILABLE/cleanup states and stops normal connection maintenance.
This proves actor/service-function loss, not necessarily Android process death.

Suggested bounded correction:

1. Classify documented request-local errors separately from true owner faults and
   uncertain native cleanup. Cancel the affected operation; do not automatically
   retry signing or authentication and do not manufacture a replacement owner.
2. Approval cancellation must keep its exact handle cursor until retirement.
   A recoverable rejection should not permanently stamp the request UNAVAILABLE:
   `NativeRequestCoordinator.kt:236` maps Cancelled/Busy back to PENDING but
   Unavailable to UNAVAILABLE. Native availability still remains blocked until
   exact cleanup actually finishes.
3. Denial reserve performs `check_denial_bound` before scope insertion
   (`denial.rs:293`). A documented pre-insertion refresh may remove an empty
   Kotlin job after confirming no cleanup obligation. A refresh after a scope
   exists must cancel that exact scope and drive SETTLE/drain; do not drop scope,
   signer, DER or approval-drain ownership just because its outcome is local.
4. Preserve shutdown for Closed/OwnerFaulted/key reconciliation failures and
   genuinely uncertain cleanup. Do not blindly copy every `retires_the_owner`
   false case from `android-bindings/src/lib.rs:118`: that predicate currently
   governs intake error scope, while some action APIs explicitly `fail_closed`
   after durable/clock faults. Distinguish actual operation stage/provenance.

## F2 — Medium diagnostic gap: actual action exception is discarded

Both approval and denial owners expose `ownerFailed: () -> Unit`. Actor wiring
hardcodes STORAGE_UNAVAILABLE and supplies no Throwable
(`ApplicationPolicyActor.kt:69,72`), even when the source was a presentation
refresh or another category. `failOwner` supports a Throwable, but these callers
drop it before reaching the existing bounded enum-based diagnostic machinery.
This prevents a later log from distinguishing an ordinary stale request from
storage, keys, native cleanup or clock failure.

Suggested correction: pass the original exception to the existing fixed failure
classification sink and retain the original action stage. Never publish exception
messages, stack text, selection IDs, notification URI, keys, DER or request body.
Logging failure must not replace the original action/cleanup decision.

## F3 — Low: one-shot notification action can be spent before admission

`NativeRequestRegistry.kt:269` claims an approve/deny notification selector before
`NativeRequestCoordinator.kt:171` queues the worker. Queue rejection, later Busy,
stale presentation or host loss can therefore spend both the OS ONE_SHOT intent
and the entry's action claim without starting the intended operation. In-app
actions do not consume this notification claim. The existing notification may
still display the action until a fresh projection/notification replaces it.
This is a concrete route-specific retry usability limitation; it does not itself
explain actor death and must not be “fixed” by replaying the consumed old intent.

If recovery is changed, issue only a freshly validated presentation generation
after definitive no-admission or actual original cleanup. Old routes must remain
consumed, and one user tap must never silently create a second signing/auth job.

## Required bounded regressions

- Inject PresentationRefreshRequired at approval begin/claim/finish dispatch:
  current actor/transport survives, affected session cancels, same handle cursor
  drains, no second auth/sign action, no false terminal PC history.
- Denial: refresh before reservation versus after scope/attempt ownership; verify
  empty-job release versus exact SETTLE/drain and retained uncertain cleanup.
- Counter-controls: Closed/OwnerFaulted/key-state failure and failed native close
  still block action admission and retire/fail the owner as required.
- Preserve error category across coordinator -> actor diagnostics with fixed
  tokens only; no arbitrary Throwable message enters evidence.
- Notification routing under background/no Activity, actual foreground resume,
  stale locator, renewed lease, duplicate PendingIntent, queue-full/Busy and host
  destruction; assert no owner construction/authentication from cold/replayed
  routes and no duplicate native signing.
- Verify recovery after non-admitted one-shot action uses a new original-handle
  presentation, not the old intent; retain same-entry duplicate refusal.

Existing tests cover route shapes, duplicate claims, host leases, drain cursors
and renderer layout. Source search found no integrated action coordinator test
that exercises a notification tap through these exception/owner-failure branches.
Those pure tests are not physical notification, biometric or UAC acceptance proof.

ROOT owns implementation, CI and later user-authorized device acceptance. No
Android offline-removal, history projection or concurrent UI edits were changed
or certified by this bounded review.

## Authorized implementation follow-up

ROOT authorized edits to three coordinator files plus a narrow policy helper and
tests. F1/F2 are **fixed at source level**, pending ROOT CI/native acceptance.

- `background/RequestActionFailurePolicy.kt` explicitly identifies request-local
  Busy/rejected/stale/presentation-refresh and existing policy/history rejection
  categories. NativeUnavailable, InvalidObservation, StorageUnavailable, Closed,
  OwnerFaulted and key reconciliation ambiguity retain owner-failure treatment.
  The stricter existing approval-cleanup classifier is separate and unchanged in
  effect: a local-looking exception during wrapper retirement cannot erase an
  uncertain cleanup obligation.
- `ApplicationApprovalCoordinator.kt`: operation-local failure cancels the exact
  session, returns Cancelled/Busy rather than permanently marking its request
  unavailable, and leaves handle retirement on its original cursor. No auth/sign
  retry is added. Genuine owner errors now pass the actual Throwable to ROOT's
  existing redacted actor failure callback.
- `DenialJob.kt`: typed local rejection cancels first and checks real input cleanup.
  Only an empty pre-insertion reserve can be removed. An existing scope enters
  cancellation-only SETTLE; uncertain/failed cleanup retains the blocker. Repeated
  local errors while already settling do not self-enqueue a retry loop; only later
  genuine progress may resume it. Nonlocal failures still fail the owner and keep
  original cleanup ownership. The original failure is preserved for diagnostics.
- `NativeRequestCoordinator.kt`: presentation refresh from the initial original-
  handle action check yields STALE and requests coalesced maintenance. It does not
  repeat the action, claim delivery or replay a PendingIntent.
- ROOT owns the matching `ApplicationPolicyActor.kt` callback signature change to
  `(Throwable) -> Unit` and passes that failure to `failOwner`. That change was
  coordinated rather than overwritten by this reviewer.
- `RequestActionFailurePolicyTest.kt` adds source regressions for local/fatal
  classification, strict approval cleanup, empty denial reserve versus owned
  scope settlement, and uncertain/closed/native-input retention. These are pure
  policy tests, not actual notification or authentication proof.

ROOT supplied the missing native-only `refresh_native_request` operation in
`android-bindings/src/effects.rs`: it admits the exact original opaque request,
checks current full binding/source/policy, then publishes Update with the same
binding/expiry. No renderer key/clock or new decision is accepted. Source inspected;
ROOT's regression checks old-handle revocation, unchanged request window and stale
old refresh refusal. No Rust product file was edited by this child.

F3 now has **bounded initial no-admission recovery at source level**, pending CI:

- `NotificationRefreshQueue.kt` retains one original borrow per request, at most
  32, for notification-only action-capacity rejection, pre-dispatch Busy or
  rejected executor insertion. It never invokes the action a second time.
- Before native refresh, the original entry must still be current and PENDING,
  with no outstanding coordinator actions and both native action slots available.
  A short admission reservation prevents a new Activity callback/action from
  racing locator replacement; it is released after the actual native call.
- Queue-insertion failure retains its ticket for actual queue progress. Native
  Busy waits for actual native/action progress and permits at most two native
  refresh attempts. Waiting for existing action cleanup consumes no native-call
  allowance and cannot create a spin loop. Invalid/revoked/expired input is dropped.
- Stop closes waiting borrows but retains any in-flight borrow until its call
  actually returns. Queue overflow never evicts another owned ticket. The native
  admission gate and existing cleanup cursors remain authoritative.
- Old PendingIntents remain consumed. The new opaque handle causes the existing
  notification owner to create a new locator/ticket; a later user tap is a new
  explicit action. Registry and PendingIntent construction were not weakened.
- This recovery does not refresh uncertain/partial action admission or infer
  cleanup completion from a rejected callback. Such attempts retain their exact
  operation cleanup; ordinary later fresh projection remains available.

`NotificationRefreshQueueTest.kt` covers one-ticket identity/capacity, no immediate
Busy retry, two-attempt cap, real-progress gating, queue insertion rejection,
stop during an actual native call and no parallel attempt on an in-flight ticket.
These tests were authored, not executed here.

Changed product paths by this child: ApplicationApprovalCoordinator.kt,
DenialJob.kt, NativeRequestCoordinator.kt, RequestActionFailurePolicy.kt and
NotificationRefreshQueue.kt (all in the background package); two new test files
under `app/src/test/java/.../background/`.
Static outcome: bounded cleanup and authority invariants retained. Actual incident
exception remains unobserved; source fixes do not establish physical reproduction.
