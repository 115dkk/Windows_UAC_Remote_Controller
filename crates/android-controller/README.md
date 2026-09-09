# Durable native phone inbox owner

`DurableInbox` joins the actual `phone-request-core::PhoneInbox` with the actual
`phone-state-store::SnapshotStore`. It exclusively owns one of each, keeps their
mutable interfaces private, and does not construct another application runtime.
The policy in the checkpoint is the sole policy source for this owner. The crate
is safe Rust and original project code is GPL-2.0-or-later.

The same owner also keeps a pure bounded `OutcomeHistory` in a versioned composite
payload. `record_pending_outcomes(native_unix_time)` records terminal projections
and removes those exact outbox rows in one snapshot commit. `history()` exposes
only the last committed view; `clear_history()` deletes visible history without
touching pending/replay/source/policy state. The native application reconciles its
queued terminal outcomes before clearing that view. See
[ADR-0006](../../docs/adr/0006-atomic-phone-history.md) for migration, clock and
failure semantics. This is not a second filesystem store or an independent
exactly-once recipient.

This is a storage/domain integration layer, not an Android runtime, notification
plugin, signing API, enrollment authority, or implementation of Windows UAC. There
are no native callbacks, network operations, private keys, FFI, renderer commands,
or boolean authentication shortcuts.

## Public interface

Native factories require actual `DirectorySynced` receipts:

- `DurableInbox::create_fresh(directory, policy, limits, boot, clock)`
- `DurableInbox::open_existing(directory, boot, clock)`

Each returns `Result<(DurableInbox, CommittedUpdate), DurableFailure>`. The
directory is the store's opaque `NativePrivateDirectory`, supplied only by the
trusted native app-data owner. File absence is not authority to create fresh
state. An open error must never be converted into a create call.

On non-Android builds only, explicitly named `create_fresh_host_model(...)` and
`open_existing_host_model(...)` factories additionally accept the store's actual
`FileSyncedOnly` receipts. These methods and their internal profile do **not**
compile on Android. There is no runtime flag that weakens a native owner. A native
factory on a weak-profile host rejects the real receipt and may leave an initial
body-free snapshot; it never silently selects the model factory or removes files.

Mutating methods are:

- `receive_opened(&VerifiedPcEvent, &mut ClockCorrelation, InboxClock)`
- `resolve_pc(&VerifiedPcEvent, &mut ClockCorrelation, InboxClock)`
- `observe_service_clock(&ClockCorrelation, InboxClock)`
- `poll(InboxClock)`
- `update_policy(NotificationPolicy, InboxClock)`
- `check_pending(RequestKey, InboxClock)`

The first five return `Result<CommittedUpdate, DurableFailure>`; the last returns
`Result<CommittedCheck, DurableFailure>`. Success wrappers expose `receipt()` and
`update()`/`check()`, or consuming `into_parts()`. Their fields are private and
their receipts come from the completed real store operation, including unchanged
commits. No caller-provided receipt can be attached to an uncommitted candidate.

Read-only `policy()`, `limits()`, `counts()`, `inbox_fault()`,
`next_deadline_nanos()`, and `is_quarantined()` all return `Result` and reject a
faulted owner. `counts()` returns only active/retained/body/recovering/source counts.
These describe the last successfully committed in-memory state; they are not a
fresh disk read or a current permission to act. `fault()` reports the fixed owner
failure category. A successfully persisted domain fault remains distinguishable
from a filesystem/codec owner failure.

## Commit-backed pending outcomes

`pending_outcomes() -> Result<&[PendingOutcome], DurableFault>` is the sole native
journal delivery source from the last committed state. `Effect::RecordOutcome`
is only a compatibility/wake hint. Original binding/issuance/outcome and stable
delivery IDs live in the same body-free checkpoint as the lifecycle transition.
Retrying rows never recreates notifications, off-hours history or old deadlines.

The recipient must durably insert/deduplicate each ID before calling
`acknowledge_outcome(id)`. This method uses the ordinary intent/candidate/commit
path and returns `CommittedOutcomeAcknowledgment` with `receipt()` and
`acknowledgment()`. Removed means a matching row was removed by that commit;
NotPending means only that this queue has no such ID. Neither proves a native
journal/OS operation. Duplicate/unknown ACK completes a no-change transaction.

A journal insertion followed by process death before ACK leaves the same ID
pending across reopen/boot change. A failed/uncertain ACK returns no committed
removal; existing dirty-intent/staging reconciliation rules still apply. This
adds no automatic recovery, journal insertion or exactly-once cross-store claim.
Native journal uniqueness/idempotency remains required integration.

The core reserves one future outcome slot per active/recovering request. If an
unexpected retention failure occurs, checkpoint encoding is prohibited and the
owner cannot release a committed update missing that outcome. ACK changes no
clock, policy, request window or fault latch. Policy-only preflight rejects pending
outcomes before consuming them; schema1 migration is restricted to fully validated
healthy policy-only state and is committed through ordinary open.

## Commit boundary and failure

Every mutable call follows one private path:

1. Reserve the store's durable intent before inspecting/mutating the domain input
   or accepting any retained/dropped disposition.
2. Run the domain transition privately; its effects/body view remain a candidate.
3. Encode the complete strict, bounded, body-free `InboxCheckpoint`.
4. Commit through the reserved guard and verify the actual durability receipt.
5. Only then return the committed update/check to the caller.

No-op transitions still finish the guard explicitly. Opening first loads a
frame-checked bounded copy (at most 384 KiB), then reserves intent before domain
decoding/restoration/polling. The restoration result is checkpointed and committed
before the new owner or its effects escape. Fresh creation first commits an empty
boot-bound checkpoint, then separately reserves/commits the initial clock poll.
It never performs that clock transition before an intent barrier.

A store or codec error irreversibly faults this owner. It calls
`PhoneInbox::stop_for_owner_failure()` to release owned body/recovery state and
returns `DurableFailure`, whose only external action is the typed
`ClearAllOwnedRequestNotifications` requirement. No failed candidate `Show`,
`Restore`, history, body view, or accepted drop/ACK is returned. The native owner
must stop intake, clear all request notifications belonging to this app, and
discard prior caller-held views and failed-candidate clock/session work. Clearing
all also covers old OS notification IDs that an invalid checkpoint cannot safely
enumerate. It is not a successful OS-delivery receipt.

The owner keeps its store/writer lock until drop even after failure. There is no
retry, reset, raw checkpoint export, mutable inbox/store accessor, rollback,
automatic recovery, staging promotion, or cleanup. An uncertain commit may have
changed the file. Read-only APIs therefore refuse to expose a failed candidate
as persisted state. An internal incomplete-transition latch also prevents such
reads if a native caller catches an unexpected unwind; an RAII candidate guard
releases the owned body state on transition unwind.

## Freshness and native responsibilities

All create/open/begin/commit work blocks. Run the owner on one native background
storage actor, not the UI thread. Calls are serialized by mutable ownership.

The supplied `InboxClock` is an observation made **before** filesystem I/O. A
successful `CommittedCheck` can already be expired when it returns; neither it
nor a commit receipt is a final OS-posting/signing permit. After I/O, the native
owner must obtain fresh suspend-inclusive native time, reconcile withdrawals and
recheck the exact request's original deadline, current policy, enrollment and
applicable native conditions immediately before posting or starting an action.
Time must also be fresh after later blocking native work. Rechecks do not extend
the request lifetime. Treat `Effect::Restore` as a no-realert reconciliation, not
another fresh `Show` or proof of native user authentication.

This is an explicit post-I/O native-action boundary, not a request to keep
committing/checking until no time has elapsed. A late native observation must
withhold the action; any resulting domain mutation still uses the transaction
methods. Repeating file I/O is not a freshness guarantee, and no final native
action-eligibility helper is implemented by this crate.

The caller must supply actual native boot/clock observations and events verified
against the currently enrolled PC/session, not merely a historically valid key.
The domain core preserves original request bindings, replay/suppression guards,
source-clock watermarks and recovery leases. Reopened active IDs have no body
until the core accepts an exact newly verified body in the permitted recovery
window. This crate never synthesizes such verification or reads a separate policy
preferences file.

The native host still owns directory/ancestor ACLs, backup/rollback policy,
fresh-enrollment authority, boot identity, clock origin including suspend,
live peer/revocation checks, OS notification reconciliation, background wakeups,
screen-lock and per-use hardware authentication, and any final request decision.
The store checksum is not a MAC and generation is not a hardware rollback counter.
Directory-synchronization receipts rely on the device/filesystem honoring its
calls; Windows model files are not Android power-loss evidence.

## Evidence boundary

Host tests use actual isolated temporary directories and actual signed synthetic
PC events, not a mocked store/domain engine. The first tracer verifies committed
off-hours suppression across close/reopen while admitting an unseen valid
cold-wake request. Additional authored cases cover no-realert active recovery,
original expiry, explicit no-op commits, snapshot-policy authority, persisted PC
resolution/source watermark, failed intent/staging, invalid/missing saved state,
committed domain faults, redacted Debug, and real Windows share-delete blockers
that prevent candidate Show/Restore/body/policy results from escaping. Native
factories reject actual Windows file-only receipts; a Linux-only case exercises
its real directory-sync receipt. The newer outbox cases cover reopen/reboot
retry, unknown/duplicate ACK, policy-only guard, preflight/rename ACK failures
and committed legacy policy migration. Only ROOT executes them.
ROOT confirmed all26 applicable durable-owner tests plus affected core/integrity
tests and all-target/all-feature Clippy. This is not native journal/device proof.

ROOT owns all execution, workspace/lock integration, fmt,
Clippy with `-D warnings`, actual Rust Analyzer, host filesystem failure tests,
Android cross-compilation and app-private-directory/process-kill/device tests.
No test written here proves actual Android OS delivery, authentication or UAC.
