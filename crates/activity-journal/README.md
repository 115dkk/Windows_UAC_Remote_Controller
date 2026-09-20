# Activity journal and atomic-owner outcome history

This crate has two distinct responsibilities. `Journal` is the existing bounded
filesystem-backed diagnostic log. `OutcomeHistory` is a pure, body-free result
projection for an Android owner that commits its inbox, history and outcome ACKs
in **one existing SnapshotStore transaction**. The pure model adds no filesystem,
network, native notification, authentication or Windows-action implementation.

## Pure outcome history API

```rust,ignore
let mut history = OutcomeHistory::new(OutcomeHistoryLimits::default());
let result = history.record_pending(&pending, native_unix_millis)?;
let bytes = history.to_bytes()?;
let restored = OutcomeHistory::from_bytes(&bytes)?;
```

`record_pending` accepts the real `phone_request_core::PendingOutcome` type, not
arbitrary event text or a claim of Windows approval. Each immutable retained row
has only its 32-byte delivery ID, the first supplied native `UnixMillis`, and the
exact `notification_policy::RequestOutcome`:

- `CancelledByPc`
- `ExpiredByPc`
- `ExpiredLocally`
- `CompletedByPc`

`CompletedByPc` must **not** be relabelled `WindowsApplied`, approved or denied.
The producer's coarse result does not distinguish those completion reasons. A
timestamp is when this native owner first recorded the outcome, not when UAC was
approved or when Windows applied an action.

`records()` exposes a bounded slice, oldest insertion first; `limits()` exposes
immutable limits. `prune(now)` removes aged rows and reports counts; `clear()`
removes visible rows and returns their count. `OutcomeHistory` is a bounded
`Clone` suitable for candidate preflight. Neither mutation, clone nor encoding
is a durable commit receipt.

## Atomic owner contract and retained-row deduplication

The integration owner must validate its existing producer, make one candidate,
record the pending outcomes into that candidate's history, remove those exact
IDs from the candidate's producer outbox, and commit both states in the **same**
snapshot before publishing any successful history/ACK result. A failure before
or during commit must not acknowledge a producer independently. The enclosing
owner must reject inconsistent state, including pending/history ID overlap, and
retain its current replay/watermark/recovery protections. None of this wiring is
performed by `OutcomeHistory` itself.

While an ID is retained, a same-ID/same-outcome retry is `AlreadyRecorded` and
does not refresh its timestamp, change ordering or prune other records. A
same-ID/different-outcome retry returns `OutcomeConflict` without any mutation.
Those checks precede pruning, including when a retry has a far-future timestamp.
The stored ID is opaque; this projection does not retain the original request
binding and cannot independently revalidate its hash or authorize an event.

Prune, clear and count eviction deliberately leave **no hidden ID receipts**.
After a row is removed, this model alone cannot recognize that ID; the enclosing
atomic owner and persistent producer replay guards must prevent reissuance.
Clearing history must never clear those producer guards. This is not independent
exactly-once delivery, rollback-proof storage, or permission to accept an
arbitrary newly supplied `PendingOutcome` after resetting producer state.
Off-hours drops create no pending outcome, so they have no route to this model.

## Retention and native wall-clock corrections

The hard limit is 512 records. Defaults are 512 records and 30 days; pure-model
limits may lower the record bound or select an age up to 366 days. Native owners
may use only defaults and reject otherwise valid non-default encoded limits.

A new record prunes timestamps strictly below
`now.saturating_sub(max_age_ms)`, then evicts the oldest insertion if necessary.
Records exactly the maximum age are retained. Explicit `prune` uses the same
rule. The count bound holds independently of time, including future-dated rows.

There is no permanent wall-clock floor and no rollback error. A backward clock
correction records the actual supplied time, leaves existing timestamps alone,
and retains future-dated rows until time catches up or count eviction removes
them. A forward correction may prune early. Later corrections cannot recover
removed data. Age guarantees degrade when native wall time is incorrect; space
remains bounded. Display/retention time must never gate monotonic authorization.
If native time is unavailable or invalid, the integration boundary must decline
the record/ACK transaction rather than fabricate a timestamp.

## Bounded binary v1 format

All integers are big-endian. `MAX_OUTCOME_HISTORY_BYTES` is 21,014:
22 header bytes plus 512 fixed 41-byte rows.

| Header field | Bytes |
| --- | ---: |
| Magic `WUACHST\0` | 8 |
| Version = 1 | 2 |
| Maximum records | 2 |
| Maximum age, milliseconds | 8 |
| Retained row count | 2 |

Each row contains ID (32 bytes), first `UnixMillis` (8 bytes), and outcome tag
(1 byte: cancelled by PC = 1, expired by PC = 2, locally expired = 3, completed
by PC = 4). Rows follow insertion order, not timestamp order.

Decode checks the hard byte cap, version, limits, configured count, exact length,
timestamp range, fixed tags and uniqueness of **every** ID before returning
state. There is no automatic pruning, migration, defaulting or reset on decode
failure. Count and exact length are checked before bounded row allocation.
No checksum or signature is added: the enclosing SnapshotStore supplies its
own framing/integrity/durability contract; neither checksum nor a parsed history
ID is authentication or hardware-backed rollback protection.

Diagnostics expose fixed categories, counts and public limits, never stored IDs,
request bodies, timestamps, raw parser text or operating-system errors. Original
code is GPL-2.0-or-later and the crate continues to forbid unsafe code.

## Verification boundary

Only ROOT runs validation. Public-interface tests use signed synthetic PC events
and the real pure PhoneInbox to obtain pending outcomes; they are not evidence
of Android persistence, notifications, phone authentication or Windows UAC.
The existing `Journal` retains its original file-lock, staging and retention
behavior, including its documented lack of directory-fsync durability.
