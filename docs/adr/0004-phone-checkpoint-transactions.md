# ADR-0004: Committed, body-free phone recovery

Status: implemented and ROOT host-tested, 2026-09-09; native Android gates open.

The notification engine exports validated metadata only. The phone inbox adds
full request binding, original mapping, phone boot observation, source-watermark
and quarantine consistency, and a non-extendable recovery visibility lease.
The byte store provides bounded framing, an exclusive writer and an independent
intent marker. `DurableInbox` is the sole composition owner and policy authority.

An input becomes eligible for domain classification only after durable intent
reservation. All returned dispositions—including off-hours drops—follow commit.
Unaccepted pre-barrier failure is not falsely labelled a persisted discard.
Failure during/after reservation leaves intent, poisons ownership, releases
request bodies and requires request-notification cleanup. No automatic reset,
old-state success claim, or local approval/signing capability is added.

Same-boot active recovery retains the original deadline but no body/approval.
It needs an exact freshly verified PC body and an unexpired visibility lease.
Restore is a silent reconciliation effect, not proof an earlier OS post happened.
New phone boots suppress previously seen IDs while preserving source-expiry
barriers; unseen cold-wake requests remain eligible. Native BOOT_COUNT, coherent
time and private storage must come from the native owner, never the renderer.

Android/Linux require file and directory synchronization. Windows exposes an
explicit weaker file-only profile for host tests; native factories reject it.
The model factory is absent from Android builds. Actual Android locking, power
loss, backup/transfer and OS-notification behavior remain unproven.

Rust 1.97's std file locking excludes Android. Android-only rustix 1.1.4 safe
borrowed-file flock is used by the new store and existing preference/journal
owners. All handwritten shared/Android Rust still forbids unsafe; dependency
internals are not claimed unsafe-free.
[Rustix flock API](https://docs.rs/rustix/1.1.4/rustix/fs/fn.flock.html).

Native authority files must use `Context.getNoBackupFilesDir()`. Explicit legacy
and Android12+ cloud/device-transfer exclusion rules supplement allowBackup=false.
No cross-platform transfer target is declared; future bindings must not move
authority state into a backed-up/shared directory.
[Android backup rules](https://developer.android.com/identity/data/autobackup?hl=en).

Remaining integration: Application-scoped single owner and generated binding,
actual Keystore/notification/clock callbacks, freshness check after blocking I/O,
trusted interrupted-store reconciliation, enrollment/revocation and durable
idempotent outcome delivery. A checkpoint commit is not an OS-notification or
activity-journal delivery receipt: commit-to-native-apply crashes still require
reconciliation/outbox handling at the native service layer. Nothing here proves
Windows applied a UAC decision or that the complete product is ready to release.
