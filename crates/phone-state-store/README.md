# Phone state byte store

This crate stores one bounded, opaque native checkpoint. It is not a database,
key vault, enrollment registry, replay-policy implementation or approval API.
The domain owner must encode only its approved non-body metadata and validate it
again after loading. The store cannot inspect an opaque payload for secrets.

## Native API

```rust,ignore
let directory = NativePrivateDirectory::from_native_app_data(native_path)?;
// Choose one explicitly; never turn an open error into a fresh state.
let mut existing = SnapshotStore::open_existing(directory)?;
let checkpoint_bytes = existing.snapshot()?;
// Decode and validate checkpoint_bytes in the native domain owner.
let transition = existing.begin_transition()?;
// Only after the intent barrier: classify intake into an unaccepted candidate.
// Do not release the candidate state/effects/ACK before the next call succeeds.
let receipt = transition.commit(next_checkpoint_bytes)?;
// Android production requires receipt.durability() == Durability::DirectorySynced.
// Only now may the domain owner release effects/acknowledgments.
```

Fresh initialization is
`SnapshotStore::create_fresh(directory, initial_bytes) -> Result<(SnapshotStore, CommitReceipt), StoreError>`.
All four fixed filenames must be absent. The host must separately establish
fresh initialization authority; file absence does not prove first-ever use.
`snapshot() -> Result<&[u8], StoreError>` returns the frame-checked cached payload,
not a fresh disk read or permission to act. `commit(&mut self, &[u8])` checks disk
against the original loaded/current frame even when the bytes are unchanged.
Receipts expose only `generation()`, `durability()` and `changed()`.
`begin_transition(&mut self) -> Result<Transition<'_>, StoreError>` returns an
exclusive borrowing guard after the intent barrier. Its only completion method
is `commit(self, payload)`. Guard Drop leaves intent and the owner faulted; there
is no cleanup/abort method. Explicit same-byte completion clears intent after
synchronizing, without rewriting the snapshot or incrementing its generation.

The store and transition are non-cloneable; the store owns its OS writer lock
until drop. The store is faulted while a transition is reserved and is restored
only after successful completion, not merely by dropping/forgetting the guard.
Run blocking open/create/begin/commit work on the native storage owner/background worker. Never
expose directory selection, raw bytes, creation, or recovery as renderer commands.
There is no automatic recovery, reset, truncation, staging promotion, or rollback.

## Fixed format and bounds

The payload cap is 384 KiB (393,216 bytes); one frame is at most 393,270 bytes.
Both file metadata and actual reads are bounded, including a one-byte oversize
sentinel. Writes cannot exceed the cap. At most one current frame and one fixed
staging frame exist, plus a zero-byte persistent lock and nine-byte intent.
Transient in-memory buffers are likewise bounded by the frame cap; no per-request
files, history, retained log, compaction, directory enumeration, or unbounded queue.

| File | Meaning |
| --- | --- |
| `phone-state.snapshot` | Committed framed checkpoint |
| `phone-state.lock` | Persistent zero-byte OS writer-lock object; never unlinked |
| `phone-state.staging` | Only the current operation's complete replacement frame |
| `phone-state.intent` | Nine bytes `WUACDIRT` followed by `0x01`; any preexisting intent blocks opening |

Snapshot format is exactly: eight-byte magic `WUACPST\0`, u16 big-endian version
1, u64 big-endian nonzero generation, u32 big-endian payload length, 32-byte
SHA-256, then exactly that many payload bytes. The digest covers the preceding
22-byte prefix plus payload, not the digest field. Unknown versions, zero
generation, bad lengths, trailing data, truncation and checksum changes fail.
Generation starts at one and increments only for changed content; overflow
fails closed. Identical-byte commits verify and synchronize, without rewriting
the snapshot or incrementing the generation.

SHA-256 detects accidental corruption, not malicious changes or rollback. A
party able to replace private app files can recompute it or restore an older
valid frame. Generation is not a trusted cross-restart monotonic counter. Native
backup/restore, fresh-enrollment and replay-cutoff rules remain domain duties.

## Commit boundary

1. Validate the pinned/trusted directory, lifetime lock, absence of prior intent
   and staging, and exact unchanged current bytes (or absence for fresh create).
2. Exclusively create the intent, write and sync it, then sync the directory.
3. Exclusively create staging, write its bounded frame and sync it. Recheck the
   lock, prior snapshot and exact newly owned staging/intent contents.
4. Close staging and atomically replace the fixed current name in the same
   directory. Verify and sync the new current file, then sync the directory.
5. Remove only this operation's owned intent and sync the directory again.
6. Return the receipt; only then update the cached state and release effects.

The independent intent is not consumed by snapshot rename. On Android/Linux it
has a successful directory barrier before replacement starts. A leftover intent
or staging file causes an explicit error on reopening; the store neither guesses
the winning version nor silently accepts the old version. If the intent's final
deletion is lost, reopening conservatively fails instead of recovering itself.

Any commit storage error poisons the current owner: subsequent `snapshot()` and
`commit()` return `Poisoned`. Oversized convenience `SnapshotStore::commit` input
is rejected before storage and does not poison it. In contrast, any failure of
an already reserved `Transition::commit`, including oversized input, leaves the
owner faulted and intent intact. A rename or synchronization failure is `CommitUncertain`: the
current file may already contain new bytes. The caller must not claim rollback,
continue using the old in-memory state, retry effects, or silently recreate files.
Creation failures may leave incomplete files, deliberately not auto-cleaned.

## Platform and private-directory constraints

Android/Linux successful receipts are `DirectorySynced`. Rust's safe file API
maps file/directory `sync_all` to `fsync`; Linux documents that a separate
directory sync is needed for directory-entry durability. This is a conditional
OS/filesystem contract, not a completed device power-loss test.

Windows receipts are only `FileSyncedOnly`, intended for filesystem model tests.
Rust 1.97 uses `FlushFileBuffers` for file sync and `MoveFileExW`/a rename fallback;
these safe std operations do not establish the Android directory-barrier
contract. The Windows intent is not claimed power-loss persistent. Other
platforms return `UnsupportedPlatform`.

Source inspection found Rust 1.97's standard `File::try_lock` does not implement
Android. ROOT approved Android-only `rustix` 1.1.4 with `std`/`fs` features. The
store uses safe `flock(&File, NonBlockingLockExclusive)` there and the lifetime
standard OS lock on Windows/Linux. Contention and OS failure are separate fixed
errors; no unlocked fallback exists. Android cross-build/device gates remain.

The host provisions the directory and protects it and its ancestors from other
writers. The constructor rejects relative/parent-traversal paths, symlinks and
reparse-point ancestors; it never canonicalizes through them or repairs ACLs.
The host must intentionally resolve any legitimate native platform path alias
before supplying this directory. Check this with Android's actual app-private
path; do not weaken the constructor to follow arbitrary frontend paths.

Files must be regular, non-symlink/non-reparse entries. Unix opens use no-follow,
nonblocking flags and mode 0600 for new files; hard links are rejected and inode
identity is compared. Windows uses no-share-delete handles for files and every
ancestor, with actual directory list access. Stable std does not supply all
Windows hard-link/ownership checks here; ACL provenance remains a native-host
requirement. Unix path-based rename still relies on trusted ancestors. Advisory
locks are not a defense against a party already allowed to rewrite the directory.

## Restart integration is not completed by this crate

The domain owner must persist original request bindings/drop guards, validate
its checkpoint schema, coordinate peer/session delivery and handle old OS
notifications. Persist before declaring a received request retained/dropped or
emitting effects/ACKs. The convenience `SnapshotStore::commit` creates its intent
only when called: it cannot protect a disposition already accepted beforehand.
Use `begin_transition` before accepting classification, keep candidate state and
effects unaccepted, and release them only after `Transition::commit` succeeds.
Until the begin barrier succeeds, input is unaccepted, not a persisted drop.
A crash before the first durable write cannot itself record that a packet was observed.
A fresh TLS connection/probe cannot alone
invalidate a replay of an old signed request. Filesystem restore/deletion and a
new phone monotonic epoch need explicit domain reconciliation, not elapsed-time
guessing, automatic defaults, or dropping every cold-start request.

## Evidence and ROOT-only gates

The initial public test exercises real isolated temp-directory
create/commit/reopen and typed platform receipts. ROOT reported this Windows
tracer test passing. Additional authored public boundary tests cover missing,
partial, corrupt, oversize and externally replaced state, writer exclusion,
generation exhaustion, link/path shape and redacted diagnostics. ROOT reported
18 Windows baseline tests passing. The transition slice adds begin/drop/reopen,
changed and unchanged completion, oversize failure, external mutations, failure
before reservation, redacted guard Debug and a real blocked Windows rename.
ROOT confirmed the first transition RED (missing API) before implementation;
transition GREEN remains pending. Synthetic bytes are not native
notification, credential, hardware-keystore, Android background or power-cut
proof. No validation was executed by the implementation child.

ROOT owns Cargo workspace/lock integration, fmt, Clippy with `-D warnings`, actual
Rust Analyzer, Windows/Linux filesystem tests, Android cross-compilation and
real app-private directory/lock/fsync/process-kill/power-loss validation. ROOT
must separately test persistence-before-effects in the domain owner and explicit
failure behavior at each synchronization/rename boundary.

Primary implementation references, read 2026-09-09:

- [Rust 1.97 Unix file sync and lock implementation](https://github.com/rust-lang/rust/blob/1.97.0/library/std/src/sys/fs/unix.rs)
- [Rust 1.97 Windows file implementation](https://github.com/rust-lang/rust/blob/1.97.0/library/std/src/sys/fs/windows.rs)
- [Linux fsync directory requirement](https://man7.org/linux/man-pages/man2/fsync.2.html)
- [Microsoft FlushFileBuffers contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
- [Rustix 1.1.4 safe flock API](https://docs.rs/rustix/1.1.4/rustix/fs/fn.flock.html)

Original project code is GPL-2.0-or-later. Dependency licenses remain their own.
