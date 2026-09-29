<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0041: A torn activity journal does not keep the service down

Status: implemented source with unit coverage. Not yet observed on the machine
that produced the evidence below; the next service start there is the check.
This changes only what the Windows service does when the activity journal
cannot be opened at startup. The journal crate, its file format, its ACLs and
the trust registry are untouched.

## Evidence

A PC lost power (Kernel-Power 41, the unexpected shutdown logged for 09:40 on
2026-09-29). From the next boot the 1.7.1 service wrote the same public
diagnostic row about every 30 seconds, more than 1,300 times:

```json
{"kind":"startup_failure","stage":3,"code":7}
```

Stage 3 is `Journal::open` in `runtime.rs`; code 7 is `JournalUnavailable`.
The phone could not reach the PC for the whole period, and it could not
approve the installer that would have repaired it either, because approving a
UAC prompt from the phone needs the service that was down.

`Journal` rewrites `activity.jsonl` through a fixed `activity.staging` file:
create, write, sync, rename. A power cut between the create and the rename
leaves the staging file behind, and from then on every open returns
`StagingRecoveryRequired`. A damaged current file returns `CorruptStorage` (or
one of the size errors) just as permanently. The crate refuses to guess on
purpose and exposes two explicit recoveries, `discard_staging` and
`clear_storage`, for its caller to choose. The service was that caller and
never chose. It also discarded the error, so the diagnostics could not say
which of the two happened; the directory is readable only by SYSTEM,
Administrators and the service itself.

## Decision

**The service chooses the recovery at startup.** A leftover staging file is
discarded and the open is retried. The current file is the last complete
rename, so this loses at most the one write the power cut interrupted. A
current file that is malformed or over a size bound is cleared, which loses the
retained history. Both are bounded: at most one discard and one clear per
start, and nothing else in the directory is read, renamed or removed.

This is acceptable because of what the journal is. The crate's own contract
says it is diagnostic history, never authorization state, and that no approval
may depend on a journal write or replay. Keeping the service down to protect
that history inverted the priority: it cost the whole product to keep a
troubleshooting log intact.

**Everything else still stops startup.** A lock held by another writer, a lock
file with content, a link or reparse point where a file belongs, and I/O
failures are not what a torn write produces. They point at a second writer, a
tampered directory or a failing disk, and the service keeps refusing to start
on them. The trust registry keeps its own stricter rule: "parsing never
recovers a last-good authority".

**The cause is recorded.** Each recovery writes a `journal_recovered` row with
the fault and the action. A failure that is not recovered writes a
`journal_unusable` row with the fault (and the I/O step for an I/O failure)
before the `startup_failure` row, so the next report from a user's PC names
the cause instead of a stage number.

## Scope

Unchanged: the journal's format, retention, locking and atomic replacement;
the ACL checks in `open_activity_directory`, which still run first and still
fail as stage 2; append failures during a run, which still end the worker. A
torn write during a run now costs one service restart instead of every restart
after it.

Not established here: that `activity.staging` was the file left on the
reporting PC. Reading it needs an elevated shell there. Both the staging and
the corrupt-file cases are recovered, and the new rows will name which one it
was.
