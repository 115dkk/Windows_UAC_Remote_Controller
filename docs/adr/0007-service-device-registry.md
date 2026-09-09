# 0007 — One service-owned, append-only device registry

Status: implemented source; ROOT CI/native evidence must be recorded separately.
This decision does not choose the pending QR confirmation workflow or activate
enrollment, phone authentication, a listener or Windows prompt approval.

## Context and ownership

The previous in-memory registry could not survive a process restart. Replaying
enrollment calls would reset/reassign revision history, including gaps and the
empty registry after revocation. Android transport keys must not be maintained
as an independently updated authority list.

approval-core now exposes bounded typed immutable checkpoints, preserving each
active DeviceId/revision/two decision keys, capacity and next_revision exactly.
The service composite adds that row's canonical P-256 transport public key. All
three roles and the PC identity key are mutually distinct across active devices.
The composite is versioned, canonical and at most5,806bytes for32devices. It
contains no private keys, passwords, request bodies, command lines or QR secrets.
Parsing public keys is not Android attestation or permission to enroll them.

The actual SCM worker owns ServiceRegistry and its retained file/directory pins,
before WorkerEvent::Ready. There is no public constructor and no Tauri/CLI/IPC
enrollment, raw-store or signing command. Rust mutation methods are future
trusted-owner seams. Their CommittedRegistryChange must be consumed while the
same owner applies the matching engine change and invalidates old transport/
handshake generations before further dispatch. That live engine/peer path is
not yet integrated; the current lifecycle worker only initializes/restores.

## Initialization

Elevated installation provisions only the fixed private trust directory under
the native ProgramData product folder. Service open never creates/repairs it.
The worker checks exact absence plus an otherwise empty validated directory.
Only the actual successful-new-PcIdentityKey branch may initialize an EMPTY
registry. Existing key plus missing/corrupt registry, or old registry plus missing
key, fails closed. No overwrite, key rotation, old-state import or retry-as-fresh.
New-key provenance is not a first-QR/UAC/enrollment grant. Normal reinstall retains
keys/trust data. Pre-registry development installations require an explicitly
reviewed migration/recovery path, not silent initialization beside existing keys.

## File transaction

One fixed devices.journal is opened synchronously with exclusive sharing on
fixed NTFS. Validate the same read/write handle, normalized fixed path, volume,
normal single-link file and private ACL; keep protected non-reparse ancestors
pinned. Caller identity is actual LocalSystem plus the enabled service SID,
with no thread impersonation. Existing trusted filesystem principals include
SYSTEM, administrators, TrustedInstaller and the service SID; this is not a
claim that administrators cannot write the file.

The header binds the exact canonical PC identity key. Each transaction consists
of a versioned consecutive-sequence intent (previous transaction hash, payload
length/hash) followed by a matching commit and full payload. A domain-separated
SHA256 digest binds the PC key, complete intent, commit prefix and payload.
The owner is closed before IO, flushes the intent, then writes and flushes the
commit. Only both successful exact-length confirmations publish the new memory
state. Any uncertainty or unwinding leaves authority closed, without claiming
rollback; later bytes may contain the old state, new state or an invalid tail.

The adapter uses FILE_FLAG_WRITE_THROUGH and FlushFileBuffers on that same
handle. This follows Windows's file/data/metadata flushing contract, not a tested
hardware power-loss guarantee. No directory rename protocol or Android store's
Windows FileSyncedOnly model is reused. Synchronous native calls can block.
[Windows file caching](https://learn.microsoft.com/en-us/windows/win32/fileio/file-caching),
[CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
[FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).

Recovery validates the entire bounded chain, canonical composite, fixed capacity
and nondecreasing allocator highwater. Any torn, unknown, malformed or trailing
record fails; there is no last-good authority fallback. The first transaction
must be empty with initial allocator/capacity. A fully valid older prefix remains
valid: hashes do not provide a trusted anti-rollback anchor. Lower-privilege
replacement is prevented by filesystem protection/exclusive ownership, not by
this format. Privileged backup/physical rollback is not claimed prevented.

## Bounds and maintenance

The file cap is4MiB and the transaction cap is512, including initial state.
Each read/parse has fixed file, row and record limits. There is no unbounded log,
automatic truncation, compaction or reset. Capacity exhaustion or an exhausted
next_revision preserves the stored value but denies authorization readiness.
If the final flushed transaction consumes maintenance headroom, publication
returns maintenance-required and keeps the owner closed; it does not claim that
the flushed mutation rolled back. A maintenance/migration procedure remains to
be designed before long-lived release; deleting trust state is not that procedure.

## Evidence boundary

ROOT tests cover typed restore, three-role/PC key separation, canonical bounds,
intents/commits, correctly hashed semantic violations, torn tails, write/flush
failure models, unwind and exhausted-owner publication. Native adapter tests
check only pure flags/metadata/bounds. Real Windows token/ACL/sharing/crash/flush,
installation/startup/recovery and whole-app UAC/authentication behavior remain
unverified until their dedicated native checks. Already-compromised SYSTEM/kernel
remains excluded by the user; this adds no new permission or threat exclusion.
