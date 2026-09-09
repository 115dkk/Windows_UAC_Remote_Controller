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

V2 also retains a bounded LocalKeyLedger in the same transaction. Preparing is
committed before any future native creation; exact observed public keys become
CreatedUnverified, not enrolled authority. Native policy-only startup preflights
keys under the store lock before V1 migration/write. No missing-key regeneration,
key deletion, additional file or Kotlin writer is introduced. Policy/history
changes retain the ledger. See [ADR0008](../../docs/adr/0008-phone-local-key-lifecycle.md).

V3 adds the phone's peer-association ledger to that same payload, not another
file/owner. Each explicit trusted-host record binds PC/device/revision, exact
local handle and both PC pins to a monotonic local association generation. V1/V2
migration supplies absent metadata only; neither key presence nor a parsed
association is an enrollment witness. See
[ADR0009](../../docs/adr/0009-phone-peer-association-ingress.md).

This is a storage/domain integration layer, not an Android runtime, notification
plugin, signing API, enrollment authority, or implementation of Windows UAC. There
are no native key/UI implementations, private keys, FFI, renderer commands, or
boolean authentication shortcuts. The optional `AssociatedPcSocket` connects the
existing real TLS/socket pipeline to current recorded associations; it does not
start a network task from the Application or relax its policy-only startup gate.

## Association-bound receiving connection

The native host records associations only after separately verifying the complete
pairing grant/receipt, endpoint/key ownership and required attestation. This crate
does not provide that ceremony or a foreign/renderer enrollment setter.
`record_peer_association_from_trusted_host` prevalidates the candidate and complete
checkpoint before intent, then publishes only after its commit. Revoke requires
the exact current generation and retains the generation highwater. Both methods
preserve inbox/replay/history/local-key state. Every local-key mutation rechecks
global PC-versus-local-role isolation; invalid candidate metadata does not start
an intent or turn a previously healthy owner into a faulted one.

`AssociatedPcSocket::new` resolves an existing association and local key tuple,
requires the supplied native CLIENT identity's exact transport key, and creates
the actual PeerTransport/SocketDriver pinned to that PC's transport key. It also
freezes the PC event-verification key and a fresh, nonpersistent owner-instance
identity. IP addresses, carrier/relay markers and TLS Ready are not enrollment.

Only its actual received TLS frames can produce a non-Clone `ReceivedPcEvent`,
after application-signature verification with that frozen key. `apply_event`
requires the same connection, healthy owner instance and current exact association
and local tuple before a domain intent. The socket wait holds no inbox borrow.
Each connection privately owns its pending clock probe and correlation; raw
correlations cannot be imported. Outbound operations are the fixed clock request
and the two sealed prepared-decision types, not arbitrary frames or signing.

Cancellation, fatal error, observed close, explicit abort and Drop invalidate
shared event/update context and clear clock state. A child cancellation token
keeps one connection's abort from cancelling unrelated PCs. Queued messages may
not create new inbox state after any observed termination, including normal EOF.
Already committed downward withdrawal/history effects still need processing;
new display requires fresh post-I/O context/request checks. No atomic rollback
is claimed for cancellation arriving during a disk commit.

`AssociatedUpdate` identifies the triggering message's source, not an approval
plan or the original source of every preexisting request affected by maintenance.
The receiving wrapper now additionally records that association's generation in
the original request guard via private source-aware durable methods. A conflicting
old/unknown source is rejected before intent without destroying the current
connection's otherwise valid clock/work. Composite validation checks all retained
source generations against the peer highwater and generation-to-PC relationship,
including inactive guards. Removed associations may remain historical metadata.

`check_associated_pending` first performs the normal committed pending check,
then returns a body only if its ORIGINAL generation resolves to the current
immutable PC/device/local-key relationship. None, removed or replaced sources
are not filled from a latest-PC lookup. The result keeps committed downward
effects even when it withholds the body. Returned AssociatedPendingRequest is a
non-Clone snapshot with owner identity, not a signing/action token or live native
freshness proof. See [ADR0010](../../docs/adr/0010-original-request-source.md).
Authenticated native intake/effect dispatch, key operations and phone
authentication remain required. Removing an association
does not itself withdraw existing Android notifications or erase replay guards.

## One-shot native approval plans

`ApprovalPlanOwner` owns one process-local slot tied to this exact DurableInbox
instance and trusted native phone boot. Begin, claim and finish require the
original associated request/current key tuple and observe fresh time after each
blocking check. The transition always carries committed downward checks, even on
rejection. No plan, attempt or authentication state is checkpointed. Cancellation
also invalidates a claimed attempt; native cleanup, not cancellation alone,
retires the slot. Strict DER verification returns a typed prepared submission,
never a Windows-success history row or delivery receipt. The containing native
actor still owns actual hardware-key/per-use authentication and current transport
handoff checks. See [ADR0011](../../docs/adr/0011-native-approval-operation.md).

`ApprovalPlanOwner::cancel_request(RequestKey)` also reaches retired-but-live
plans/submissions and contexts retained only by a queued socket guard. It matches
the complete PC/epoch/request key, changes only existing downward flags and never
touches inbox/replay/history state, clocks, native APIs or other requests. Its
count-only `ApprovalRequestCancellation::matched_contexts` includes already
cancelled live matches; it is not provider/UI quiescence, a PC result or proof
that bytes were unsent. Cancellation does not retire an occupied native slot.

The owner tracks at most `MAX_LIVE_APPROVAL_CONTEXTS = 64` private weak contexts.
Retirement and cancellation do not remove live entries; only dropping the LAST
plan/attempt/submission/delivery-guard reference releases capacity. Each successful
begin registers once before publishing its slot/handle. A free-slot begin reserves
capacity before its blocking check; `ContextCapacity`/`ContextAllocationFailed`
reject without discarding another context or starting that check. An occupied
native slot still reports Busy first. Close/Drop's original shared lifetime
invalidates all contexts, not just the current slot; a new owner cannot rearm them.

This is cancellation of existing contexts, **not** a future-plan/action fence.
Before a future native Deny calls it, that actor must reserve its same-request
action fence, prevent new approval admission, cancel/quiesce the actual native
UI/provider, and retain that fence through denial. A later same-request begin is
still possible through this pure API after cleanup if the caller installs no
fence. No native/ABI/UI fence or preemption is activated by this method.

`AssociatedPcSocket::queue_approval` now performs fresh committed original-request
checks and admits only the typed prepared signature. Its queue retains original
cancellation and a process-local request lease through actual partial TCP writes;
registration/request withdrawal or owner failure invalidates retained output.
Queued and WrittenToSocket are not PC acceptance/Windows results. A bounded retry
returns the same signature/deadline. The native foreground owner must still drive
socket/policy/time-change wakes; the API does not start that owner automatically.
See [ADR0012](../../docs/adr/0012-bound-native-transport-and-send.md).

## Request-bound denial preparation

`DenialOwner` uses one process-local `begin -> DenialAttempt -> finish` slot;
there is no approval-plan claim or wait-for-authentication stage. It consumes the
existing observational `ApprovalClock`/`ApprovalTime` contract, not an auth event.
Begin binds the original mapped window/boot, original receiving generation,
recipient device, current association and exact local public-key tuple. Its
`NativePeerLease` also withdraws retained handles on actual domain/association
changes, durable-owner failure or Drop. A lease alone is not a timer or permission.

The attempt exposes only fixed canonical `DecisionPurpose::Deny` signing bytes.
Finish consumes its slot before checking returned DER, verifies only with the
current original DENIAL public key, and observes fresh native time after blocking
maintenance and signature verification. It cannot accept Approve-purpose bytes
even when signed with the denial key. Cancellation is immediate/downward-only;
the containing native owner must confirm actual key-operation quiescence before
`retire_after_native_cleanup` permits slot reuse. Retirement alone preserves a
valid `PreparedDenial`, whereas explicit cancellation or either owner closing
invalidates it. Callback/clock/boot and durable faults do not rearm the owner.

`DenialTransition` retains every committed downward check on rejection, including
post-I/O expiry or schedule withdrawal. No local prepare/sign operation resolves
the request or records a Windows-denied outcome/history row. `PreparedDenial` is
non-Clone and is signature data, not remote acceptance. Its consuming data
extraction is not a send permit: the typed sender takes the prepared value itself
and retains its original context rather than using that extraction.

This slice does not wire Application/UniFFI/Kotlin/UI and does not change
policy-only startup. Before user-denial key use, the future native
owner must freshly require configured secure screen lock and cancel/quiesce
concurrent approval UI and any retained same-request approval transmission. The
DENIAL operation itself must not request BiometricPrompt/per-use authentication.
Public key metadata and software-signature fixtures are not hardware-policy or
enrollment proof. The new host tests are authored for ROOT execution only.

### Guarded typed denial delivery

`AssociatedPcSocket::queue_denial(owner, PreparedDenial, native_clock)` now uses
the same complete admission pipeline as `queue_approval`. A closed private
`PreparedDecisionRef` enum has exactly those two sealed inputs; there is no public
trait, arbitrary statement, purpose, signing or raw-frame admission. Approval's
public API and tests are unchanged. Both purposes share one private progress
record and the same driver output slot, which also carries the fixed clock probe.
Admission is Busy while either the progress record or driver frame is pending;
it cannot overwrite a prior purpose's ticket before actual drain/terminal cleanup.

Denial has separate `DenialSendTransition`, `DenialSendOutcome`, `QueuedDenial`
and `DenialWriteProgress` types. Retry returns the same prepared signature,
original window and deadline without another key operation. Admission rechecks
owner/current original association/local keys/request window, authenticated service
epoch/correlation age, native boot/time, policy and the existing bounded request
lease. Committed checks remain available on rejection. The socket deadline is
the original remaining native lifetime and can only shorten its ten-second frame
limit; no retry or other purpose extends it.

The send guard retains the original denial cancellation, owner lifetime and
request lease, plus the newly checked lease and connection state, through TLS
buffering and each partial TCP write. Native-slot retirement does not release
that guard. The native actor must continuously drive the socket and policy/time
wakes; this change adds no background task or native timer. Cancellation cannot
recall bytes already handed to TCP. Queued/WrittenToSocket remain local facts,
never PC acceptance or a Windows-denied history row. Actual native denial key use,
cross-approval cancellation/preemption, application dispatch and PC decision
handling are separate integration obligations, not activated by this API.

## Public interface

Native factories require actual `DirectorySynced` receipts:

- `DurableInbox::create_fresh(directory, policy, limits, boot, clock)`
- `DurableInbox::open_existing(directory, boot, clock)`
- `DurableInbox::open_existing_with_key_preflight(directory, boot, clock, preflight)`

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

### Full versus policy-only native key preflight

`open_existing_with_key_preflight` is a source-level full request-bearing restore
seam, not live intake or a change to Application/UniFFI startup. Its callback has
type `FnOnce(&ControllerCheckpoint) -> Result<(), DurableFault>` and runs under
the existing SnapshotStore writer lock. The unchanged full path orders work as:

1. Open/validate the outer byte-store frame and retain the exclusive lock.
2. Reserve durable intent before decoding the controller/domain checkpoint.
3. Decode strictly, then call native key preflight once on that immutable original
   checkpoint, before any restore, migration commit or candidate-effect release.
4. Restore using the supplied native boot/clock, encode/commit the full composite,
   require the actual DirectorySynced receipt, and only then return owner/update.

A rejected or unwinding **full** preflight can therefore leave a durable intent;
it must not be treated as a harmless policy-only preview rejection. The caller
owns partial native-key-reference cleanup, and must obey the returned failure's
notification cleanup requirement. Missing/corrupt/dirty state never becomes fresh
initialization or a policy fallback. A failure after an actual commit, including
an insufficient durability profile, does not prove the old disk state survived.

On non-Android targets only,
`open_existing_full_host_model_with_key_preflight(...)` uses the same full ordering
with the existing explicit host-model receipt allowance. It is cfg-excluded on
Android; no runtime switch selects that weaker profile. **The pre-existing**
`open_existing_host_model_with_key_preflight(...)` **remains policy-only**: it
rejects request-bearing state before callback/intent and is not renamed or widened.
Likewise `open_existing_policy_only_with_key_preflight` and its native callers are
unchanged. Existing strict legacy migration restrictions still apply in both paths.

The new host tests use actual isolated stores and synthetic public keys/events to
cover lock/intent ordering, callback rejection/unwind, domain-versus-frame errors,
request-bearing body-free recovery, post-preflight commit failure and real host
durability profiles. They do not establish hardware-key verification, enrollment,
notification delivery or Android durability. ROOT alone executes these tests and
the Android compile gate; adding these factories does not activate a dispatcher.

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
3. Encode the complete strict, bounded four-component controller checkpoint.
4. Commit through the reserved guard and verify the actual durability receipt.
5. Only then return the committed update/check to the caller.

No-op transitions still finish the guard explicitly. Opening first loads a
frame-checked bounded copy (at most 384 KiB), then reserves intent before domain
decoding/restoration/polling. The restoration result is checkpointed and committed
before the new owner or its effects escape. Fresh creation first commits an empty
boot-bound checkpoint, then separately reserves/commits the initial clock poll.
It never performs that clock transition before an intent barrier.

Local-key and association metadata inputs additionally validate detached
candidates before reserving their intent. Policy-only native preflight still
runs under the same store lock before migration writes; full recovery preserves
intent-before-domain-decode ordering. These are distinct paths, not a blanket
permission to move every recovery check before its intent.

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
