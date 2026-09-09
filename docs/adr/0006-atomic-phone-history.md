# Atomic phone history in the existing owner snapshot

Status: implemented source; target CI/native evidence is recorded separately.

The native phone owner already persists a body-free pending outcome outbox with
its replay/source state. A separate history file would require durable dedup
receipts surviving a crash between history insertion and producer ACK, including
history pruning and user clear. Instead, `DurableInbox` now owns pure
`OutcomeHistory` and commits both in its existing `SnapshotStore`.

The composite payload has a strict versioned envelope, nested lengths, fixed
512-record/default-retention history profile and the unchanged 384KiB total cap.
The history encoding itself is at most 21,014 bytes. Recorded/pending ID overlap
is invalid: a partial two-store delivery cannot occur in this representation.
Every owner mutation writes the entire envelope. Raw legacy inbox payloads migrate
only when fully valid policy-only state establishes that no request/history
reconciliation is being silently skipped. Missing, partial or unknown state is
never initialized as a successful empty store.

`record_pending_outcomes` inserts body-free projections and acknowledges those
exact producer rows in one commit. A failed/uncertain commit yields neither a
history view nor an ACK and latches the owner. The old explicit ACK remains only
for trusted external-recipient integrations; the Android application does not
expose it. `RecordOutcome` effects remain wake hints, not a second history writer.

History contains opaque delivery ID, actual phone first-recorded UNIX time and
coarse terminal outcome. It is not Windows occurrence time, authorization or proof
of successful elevation. Valid backward wall-clock corrections are accepted;
future-dated rows survive age pruning and insertion order supplies the count cap.
Request expiry still uses separate strict monotonic/source clocks. Clearing history
never clears source watermarks, replay guards, keys or policy. The pure history's
dedup lasts only while a row is retained; the atomic producer owner supplies replay
protection after prune/clear. No rollback-proof/exactly-once external system claim.

The one Application worker uses generated ABI3 history read/clear commands and an
OS wall-time callback. It explicitly initializes UniFFI contract/API checksums
before its coarse version check and controller creation. Invalid/unavailable
history time is rejected before intent/ACK and does not stop the policy owner.
Other storage, transport or malformed bridge failures are not hidden as a healthy
partial snapshot. The UI never labels coarse PC completion as approval.

Native clear reconciles queued terminal outcomes first, then clears visible
history under one application admission (two commits). Failure in either phase
does not report successful clear or claim that earlier commits rolled back.
The future request dispatcher must invoke outcome recording during background
lifecycle processing; UI reads alone are not a background-delivery implementation.
The existing policy-only startup guard remains until that dispatcher is complete.

This does not implement enrollment, native request intake, notifications, per-use
authentication, UAC action, service launch activation or a release. Physical
Android lifecycle and actual UAC/authentication acceptance remain separate gates.
