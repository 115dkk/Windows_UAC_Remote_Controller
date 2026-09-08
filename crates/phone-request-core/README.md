# phone-request-core

SPDX-License-Identifier: GPL-2.0-or-later

Bounded, safe Rust receive/drop/expiry orchestration for one phone owner. It
combines signature-verified service messages, conservative clock correlation
and `notification-policy`; it does **not** prove enrollment, native screen lock,
notification delivery, OS authentication or Windows applying a decision.

Status: ROOT host contracts checked; native Android integration remains pending.
Only ROOT runs formatting, builds, tests, Clippy, Rust Analyzer and device checks.
Current recovery/codecs have 54 host tests; these are not installed-app evidence.

## Inputs and public API

```text
InboxClock::new(ClockReading, native_phone_nanos) -> Result<InboxClock, InboxIssue>
PhoneInbox::new(NotificationPolicy, CapacityLimits) -> PhoneInbox

receive_opened(&mut self, &VerifiedPcEvent, &mut ClockCorrelation, InboxClock)
  -> InboxUpdate
resolve_pc(&mut self, &VerifiedPcEvent, &mut ClockCorrelation, InboxClock)
  -> InboxUpdate
poll(&mut self, InboxClock) -> InboxUpdate
update_policy(&mut self, NotificationPolicy, InboxClock) -> InboxUpdate
check_pending(&mut self, RequestKey, InboxClock) -> InboxCheck
observe_service_clock(&mut self, &ClockCorrelation, InboxClock) -> InboxUpdate

request_key(RequestBinding) -> RequestKey
```

`InboxUpdate` has read-only `effects()`, `issue()` and `fault()` accessors. It
preserves withdrawals even when processing also reports an issue; apply effects
before using a request view. `InboxCheck` provides `update()` and `request()` or
`into_parts()`. `PendingRequest` exposes an original immutable window/binding,
current `PendingNotification`, and a borrowed `Arc<RequestContent>` only after
the current check. There is no unchecked collection of request bodies.

The native owner chooses the currently enrolled PC key and confidential session
used to produce `VerifiedPcEvent`. The type's constructor/signature check is not
a paired-registry or native-origin proof. `ClockCorrelation` must match the PC
and service epoch. The phone clock must be a fresh native processing observation
in one unchanged monotonic epoch; `ClockReading.monotonic` must equal floor of
native nanoseconds divided by 1,000,000. Its local weekday/minute comes from the
phone's current timezone. UI/relay/wall-clock values cannot supply these inputs.

Secure-lock and native permission gating remain upstream responsibilities. This
crate accepts no authentication boolean, Keystore alias, signature creation,
credential, arbitrary execution, notification mutation, network or storage API.
All first-party code forbids unsafe. No raw signed-wire bytes are retained.

`observe_service_clock` accepts an already signature-correlated source observation
without manufacturing an application event or changing the phone clock. The
native processing time must not precede probe completion; a faulted correlation
fails closed. The maximum observed service tick is kept per complete PC/epoch
pair. An older valid sample cannot lower it. This source-past-expiry fact does
not decay just because a correlation is too old for mapping a new request;
current enrollment/epoch provenance remains the caller's separate obligation.

`source_count()` reports retained source slots. `is_quarantined()` distinguishes
an active quarantine from `quarantine_until_nanos()`, which returns only a future
phone-time wakeup hint. The latter can be None while source proof is missing.
`next_deadline_nanos()` includes active display expiry and cleanup times that
already have the required source proof; it never reschedules an old upper
estimate while waiting for an authenticated source sample.

## Original maps, bodies and replay guards

Each key uses all 256 bits of PC identity, service epoch and request ID. While
retained, the **entire** RequestBinding and original ServiceTick issuance must
match a duplicate or resolution, including changes smaller than a millisecond.
Different session/nonce/content/expiry values cannot replace an existing body.

A successfully mapped first event retains that original `MappedRequestWindow`.
Later Opened/Resolved inputs use it without a fresh mapping—even when the
conservative lower expiry has passed or the current probe is more than five
minutes old. Nanoseconds are floored to milliseconds for the policy engine;
expiry is never rounded up. A below-one-millisecond remaining window may be
conservatively discarded. Native display uses the checked notification deadline,
not a rounded-up original-nanosecond deadline.

The inbox takes an Arc body reference **only** when `NotificationEngine` admits
an allowed active request with Show. Off-hours, explicit Never, capacity drops,
closures, mapping failures and suppressed requests retain no body. Schedule
withdrawal, resolution, local expiry or a latched fault immediately drops the
inbox's body reference. Caller-owned checked snapshots can still hold an Arc;
the native owner must discard those on withdrawal. A snapshot is not permission
to display, authenticate, sign or approve later.

Local expiry alone is not a sufficient time to delete a replay guard: a newer
probe may produce a later mapping. For the first event the inbox separately
computes the following phone-time estimate:

```text
original_upper_expiry = original_probe_phone_received
                      + (original_service_expiry - original_service_sample)
```

Backward/past-source differences saturate at zero; forward addition overflow
fails closed. This estimate is never recalculated for a retained request. It
cannot by itself certify service expiry: two monotonic clocks need not advance
at exactly the same rate. A guard retires only after BOTH its original phone
upper estimate passed AND a signature-correlated sample for that exact PC/epoch
reached the original service expiry. No guessed drift margin is used.

Source watermarks remain after individual guards retire. An event with expiry
at/below the retained watermark is rejected even if an older correlation would
map it into the future. First mapping failures also keep body-free guards when
the phone upper estimate already passed but source expiry is not established.
The extra guards remain a metadata-only superset of the notification engine's
tombstones, not a new deadline for notification or approval.

If source expiry is proved before the local display estimate, the inbox sends
the existing typed PC-expiry transition to the notification engine, withdrawing
the body and recording at most one expiry outcome. It does not feed a fabricated
future phone timestamp. The wrapper stays body-free until the original upper
estimate also passed, preserving engine/cache bookkeeping. The mapper's local
lower/upper estimates still require native timing review; PC authorization uses
its own actual deadline regardless of phone display estimates.

Every retained record, active or body-free, shares the configured
`CapacityLimits.max_retained` budget (maximum 512). Body count matches the engine
active count (maximum 32). Source/epoch watermark slots have a separate bound of
that same configured count; their history is never silently evicted, even after
all guards retire. Exceeding the source-slot bound permanently faults the inbox
and withdraws active bodies. This is an explicit availability tradeoff until a
future reviewed native epoch/delivery lifecycle can retire source history.

When guards fill the budget, global quarantine protects untracked identities.
It retains the largest phone upper estimate plus bounded per-source maximum
service-expiry barriers. It ends only when the phone estimate passed and EVERY
dropped source has a sufficient watermark. New valid traffic can extend these
barriers; an old sample cannot reopen admission. Existing guards remain usable
and are not evicted. A new estimate more than 130 seconds into the phone's future,
or arithmetic overflow, fails closed; this is an input budget, not a physical
equal-rate-clock proof or a promise to forget guards after 130 seconds. Waiting
for source evidence can last longer without retaining request bodies or growing
beyond the guard/source bounds.

Known requests bypass new-map/new-guard admission. A closed or retired record
never calls receive again to become active. The implementation checks bounded
cache/engine count consistency and faults on an inconsistent active-body state.

## Resolutions and effects

- A signed resolution received before Opened establishes a body-free guard and
  cannot produce Show or user-history outcome. Later Opened cannot resurrect it.
- An unknown old resolution is dropped without body/notification/history. If
  only phone-time estimates are past, a body-free exact binding/issuance guard
  still covers that uncertainty. A retained source watermark at/after its expiry
  can instead reject it without allocating an individual guard.
- Existing expired resolution uses original metadata and polling: local expiry
  generates at most one outcome, and a late resolution does not retime or add a
  second outcome. Duplicate resolutions remain drops.
- Cancellation and PC expiry map to the engine's corresponding typed outcome.
  Approved, Denied and Failed all map to **terminal CompletedByPc**, not to a
  claim of successful approval. The original verified service event remains
  the owner's source for distinguishing those terminal results. Do not label
  `CompletedByPc` alone as "Windows approved".
- Off-hours/disabled/capacity drops and schedule-change withdrawals do not create
  user-history outcomes. The inbox stores no user history itself. A poll that
  also expires some *other previously admitted* request may legitimately return
  that request's existing engine RecordOutcome; do not confuse it with the drop.

Native clock regression, including regression within the same millisecond,
latches a typed `InboxFault`, withdraws all active bodies without invented
history and permanently closes this inbox. Correlation, range and source-capacity
failures are likewise explicit. For a wrapper-detected fault the invalid engine is disposed
instead of feeding it a fabricated clock to trigger its private latch. Actual
engine faults/effects are forwarded. No public reset or clear-fault API exists.

## Body-free restart checkpoints

`with_phone_boot(policy, limits, PhoneBootId)` binds the native nonnegative
Android BOOT_COUNT observation. The ordinary `new` constructor remains a
process-only API and cannot produce a checkpoint. `checkpoint().to_bytes()` and
`InboxCheckpoint::from_bytes()` use a strict, versioned, <=384KiB binary format
with <=16KiB required-field policy JSON; no body/command/private-key bytes are
included. Structure checks are not storage authenticity or native provenance.

`restore_checkpoint(checkpoint, current_boot, clock)` returns an inbox and an
uncommitted update. On the same phone boot, previously active metadata has no
body and is counted separately by `recovering_count()`. An exact reverified PC
event is required to regain a view; the original deadline is retained and
`Effect::Restore` requests silent native reconciliation, not a fresh alert.
Source expiry, local expiry, faults and visibility-lease expiry also retire
body-free recovering IDs. Closed/discarded records never rehydrate.

Recovery leases cannot extend the original request or first continuous allowed
window. Existing minute-only observations conservatively subtract the uncertain
sub-minute portion; in the last allowed minute an old request may be ineligible
for recovery, while a valid unseen request is still admitted normally. Detectable
civil-time/monotonic discontinuities invalidate old leases. This is not a claim
to observe every clock change that occurred while the process was absent.

A different phone boot discards incomparable old local mappings and retires only
previously seen request IDs. Source watermarks/quarantine barriers and faults
survive. New unseen requests, including a valid request issued before the fresh
probe that woke the app, are not subjected to a blanket startup cutoff.

`android-controller::DurableInbox` owns the actual store transaction: reserve
durable intent before accepting/classifying a transition, then persist the
checkpoint before returning its disposition, effects or checked view. Input
rejected before that barrier is unaccepted, not a committed drop. Interrupted or
uncertain transactions require recovery, never default-empty state. Post-I/O
fresh native time and OS eligibility must still be checked before real actions.
The checkpoint's policy is the sole authority of this owner, not a separately
committed preference file. Native authority files belong in no-backup storage.

## Remaining native restart integration

The native owner must supply real boot/clock/private-directory provenance, cancel
or reconcile only this app's old request notifications, use the durable owner,
and reverify current enrollment before delivering events. A fresh TLS session
or clock probe by itself does not remember a previously discarded binding.

The test `reconstruction_explicitly_does_not_claim_durable_replay_protection`
demonstrates the still-unsafe legacy empty-reconstruction path, not a passing
product requirement. This crate does
not use the shortcut of dropping every valid new cold-start request. ROOT must
keep restart delivery/persistence and real cold-start notification behavior as
unfinished owner work; this implementation is not end-to-end completion.

## Required ROOT checks

After adding the workspace member, ROOT runs the public-interface tests, fmt,
Clippy `-D warnings`, real Rust Analyzer diagnostics and affected workspace gates.
Tests use synthetic signed PC fixtures, not real credentials/paired devices.
They cover allowed/default/alert modes; off-hours/body release; schedule change;
new-probe original-window preservation; slower/faster clock drift; source-proved
guard/quarantine retirement and persistent watermarks; source-slot exhaustion;
binding/issuance conflicts; pre-open and old resolutions; PC/local expiry and
one-outcome behavior; max/excess identity traffic; clock faults; distinct peers/
epochs; stale read-only views; and the explicit restart gap.

No pure test is evidence that Android posted/withdrew a notification, required
OS authentication, protected keys, or that Windows applied a live UAC decision.

SUPERLOOPY_EVIDENCE: .superloopy/evidence/phone-inbox-implementation.md
