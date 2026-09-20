<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0035: Recover from an interrupted pairing instead of closing the phone

Status: implemented source; ROOT device and CI evidence is recorded separately.
This supersedes the two closure rules quoted below from [ADR0008](0008-phone-local-key-lifecycle.md).
It does not change enrollment, signing, attestation adjudication or any UAC path.

## Evidence

A real Samsung SM_S948N running v0.1.0-alpha.23 died during its first QR
pairing and never opened again. The device's own records establish the chain.

JNA attaches the Rust ceremony thread to the VM for the `createLocalKeySet`
callback and records that it must detach it when that callback returns. The
Kotlin callback re-enters Rust for its input, Rust observes the presentation
clock through a second callback, and the inner return detached a thread whose
Kotlin frames were still running. ART aborted the process:
`attempting to detach while still running code`, with `presentation_clock`,
`take_input`, `createLocalKeySet` and `run_ceremony` all live on the stack.

The ceremony therefore died between its durable Preparing row and any observed
creation. The next open reserved its durable intent before the key preflight,
the preflight refused for the Preparing row it found, and the intent stayed on
disk: `UAC_NATIVE_STARTUP_V1 stage=OPEN_EXISTING reason=STORE_RECOVERY_REQUIRED`
on every start after that, with `gate=false reason=phase_CLOSED` in the client.
Nothing in the product could clear either artifact, and the screen told the user
to install a newer version, which could not have helped.

## Decision

**A nested foreign callback must not detach its thread.** One JNA
`CallbackThreadInitializer(daemon, detach=false)` is registered for every slot
of the generated vtable, once, after the generated contract check and before any
ceremony can run. This changes JNA's detach policy and nothing else: no
capability, no key, no store, no authorization. JNA still detaches the thread
when the thread itself ends.

**An interrupted commit is resolvable; a tampered one is not.** A leftover
intent or staging file now reports `InterruptedCommit`, and a written-to lock
file keeps reporting `RecoveryRequired`. `SnapshotStore::recover_interrupted_commit`
takes the same writer lock an ordinary open takes, confirms the intent file's
own fixed body, removes only the two fixed leftover names, synchronizes the
directory and opens whichever snapshot is on disk. The committed name is never
created, rewritten or renamed, so the frame a completed rename published stays
committed and an absent one is refused rather than invented. The bridge resolves
this at most once per open and fails closed on everything else. This resolves
storage artifacts only and asserts nothing about which domain effects the
interrupted operation released.

**An abandoned preparation is discarded, not preserved forever.** ADR0008 said
a failed observation write "does not authorize deleting aliases" and that
"Preparing is reconciliation-required regardless of alias presence". The first
clause stands for a failure inside a live ceremony: that path still rolls back
nothing and retries nothing. The second becomes: startup reconciliation deletes
exactly the aliases of the handles this controller committed as Preparing and
never observed as created, then commits those rows away. Such a row can name no
enrollment and no recorded set, so the keys it may have created are unusable by
construction, and the phone's only alternative was to stay dead.

The deletion runs before the commit, never after. A ledger that forgot the
handle first could never claim the aliases it left behind, while repeating a
deletion is safe: an absent alias is success. The native owner receives the
recorded handles alongside the abandoned ones and refuses a request naming one
of them, so a caller defect on the Rust side cannot destroy a recorded set.
A configured secure lock is deliberately not required for that deletion, because
a phone that lost its lock must still be able to abandon an interrupted pairing.
Aliases that no committed row claims are still refused, never adopted and never
deleted: surviving aliases do not become a new phone.

## Scope

Unchanged: enrollment, attestation adjudication, the single-use ceremony slot,
the commit-before-exposure rule, the fresh-start marker and `has_device_keys`
rules, and the refusal to regenerate, import or replace a key. No reset, no
factory path and no user-facing delete exists. The user-visible copy for a
failed owner start now describes a full app restart, which is what runs these
resolutions, instead of an update that cannot.
