# ADR0021: Durable Android lifecycle activation with a stable wake receiver

Status: accepted for implementation; native validation pending.

## Context

ROOT's retained d45b6ac lifecycle evidence showed the explicit-stop receipt with
the old component disabled and the native actor closed, followed by a real
post-reboot READY service and an enabled legacy receiver. The global application
barrier also ended in failure; neither result is waived. The evidence does not
distinguish PM persistence loss from every possible external/framework cause.

Both former product writers used only DONT_KILL_APP. Although the public
SYNCHRONOUS flag promises immediate persistence, pinned Android16_r1
PackageManagerService's flush method calls Settings' one-argument overload,
which schedules asynchronous writing. Same-state setters can also return without
flushing. No product claim may treat a cached PM readback as a durable receipt.
The exact CI image's implementation has not been established from this source.

## Decision

- `ControllerBootWakeReceiver` remains manifest-enabled, nonexported and
  direct-boot-aware, with LOCKED_BOOT_COMPLETED, BOOT_COMPLETED and
  MY_PACKAGE_REPLACED filters. Product code never changes its enabled state.
- The old `ControllerBootReceiver` is filterless/nonexported and does nothing.
  Its state is read only for migration. All product PM setting writes are removed.
- One private device-protected no-backup record contains only `v1:on` or
  `v1:off`, with a terminating newline. It has no credentials, identifiers,
  routes, notification policy, pairing data or authorization state.
- File size and exact encoding are bounded. A partial replacement, corruption,
  unsupported version, nonregular file or read error is unavailable. No automatic
  repair or explicit START overwrites such uncertainty.
- Migration is closed: missing+legacy DEFAULT commits ON, missing+DISABLED
  commits OFF, missing+ENABLED exposes LEGACY_MISSING with no automatic start.
  Explicit trusted START may resolve only that known missing legacy case.
- Existing ON/OFF is observed once per Application initialization. Automatic
  Activity, boot/update and sticky paths never change an existing choice. They
  wait for bounded actual initialization and recheck current lifecycle conditions
  and the stable wake component. OS force-stop or component disable is not bypassed.

## Ownership and ordering

An Application-owned worker performs all record I/O; no disk work or worker wait
is added to main. It is separate from the Rust/CE policy actor because boot
eligibility must be readable before first unlock. Initialization has one original
five-second budget and at most eight waiting continuations. Boot receivers retain
their real `goAsync` result until the bounded continuation; an existing sticky
Service is foreground-promoted before waiting. Neither path launches an Activity.

Explicit mutation admission requires the current real foreground Activity, fixed
operation, original elapsed-time deadline and one Application-wide ticket. A
bounded per-physical-plugin STOP reply may coexist with a START reply so downward
cancellation is not hidden behind the earlier plugin call. There remains exactly
one persistence mutation slot, with no replacement writer while it is unresolved.

START commits and freshly reads ON. Before FGS request, main rechecks the same
Activity, ticket outcome, original deadline and actual activation/wake observation.
Activity retirement or timeout revokes continuation but does not claim to cancel
an entered OS/file operation. Its slot remains until actual completion. A failed
post-commit continuation may have left ON committed; this is reported unavailable,
not rolled back or blindly retried.

STOP invalidates start generations, cancels a pending START continuation and
immediately attempts owner/service shutdown. It still attempts permitted OFF
persistence when downward native work failed. Success requires the actual native
stop observation, OFF commit/reopen, stable wake availability and the original
deadline. A busy writer means unavailable, even though downward cleanup proceeds.
After actual completion, a new explicit STOP may be admitted; no hidden retry is
queued. The first failed obligation is not converted into success by a later one.

Commit uses a fixed new partial file, checked file sync, checked directory sync,
atomic replacement, checked directory sync and a newly opened bounded readback.
A same-state retry also reopens without create/truncate, checks native file force,
checks directory sync and reads back. Leftover partial files are retained as
uncertainty, not erased to manufacture a clean state. These are Android/Java API
completion checks, not a universal storage-hardware power-loss guarantee.

## Observation and validation boundary

The existing renderer contract is unchanged. Its `bootEnabled` projection now
requires the DE choice and current wake availability; pending/uncertain state is
not ON. Existing Service.dump adds only three bounded cached fields:
`activation_state`, `activation_pending`, `activation_uncertain`. Raw
`boot_component` and native receipt `component` refer to the stable wake receiver;
they normally remain DEFAULT in both ON and OFF. Native receipts separately bind
activation ON for READY and OFF for stopped. Absence/legacy ambiguity cannot
stand in for a freshly loaded OFF receipt.

JVM tests cover exact file shape/reopen, approved migration, partial/corrupt/error
rejection, sync failure and same-state retry, original deadlines, cancelled but
retained tickets, downward failure and policy admission. They are not Android
Direct Boot or real persistence evidence. ROOT must run the real product sequence,
including immediate stopped reboot/update and first unlock, with strict terminal
barrier completion and existing source/APK/nonce/process gates. No test execution
or native success is asserted by this implementation ADR.

Sources: [PackageManager API](https://developer.android.com/reference/android/content/pm/PackageManager#SYNCHRONOUS),
[Android16_r1 PackageManagerService](https://github.com/aosp-mirror/platform_frameworks_base/blob/android-16.0.0_r1/services/core/java/com/android/server/pm/PackageManagerService.java#L3877),
[Android16_r1 Settings](https://github.com/aosp-mirror/platform_frameworks_base/blob/android-16.0.0_r1/services/core/java/com/android/server/pm/Settings.java#L2163),
[Direct Boot](https://developer.android.com/privacy-and-security/direct-boot).
