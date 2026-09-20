# ADR 0005: One Application-owned Android policy runtime

Status: implemented in source; packaging and native runtime evidence tracked in
PROGRESS.md. This is not the completed notification/authentication/approval path.

## Ownership

ControllerApplication owns one bounded worker, one generated MobileController and
one DurableInbox. The Activity/Tauri shell no longer opens the old preference
writer. Read/save commands use a narrow, strict native reply envelope; only the
Rust-returned committed policy becomes a successful response. Device and request
collections remain unavailable until their real owners are connected.

The old policy is a versioned JSON document at Application.dataDir, as verified
from Tauri 2.11.5's Android path implementation. Kotlin observes this fixed path
without mutation, checks staging/regular-file/size/UTF-8 constraints, and Rust
performs the strict document migration. It is never silently replaced by defaults.

## Bootstrap and failure

The Application constructor holds the component owner lease before callbacks.
Any existing checkpoint/lock/intent/staging or valid first-attempt marker selects
open, never create. Fresh initialization additionally requires no controller key
aliases and valid old preferences, if any. A marker is written and synced before
the initial snapshot. Interrupted or corrupt state is retained and reported, not
deleted or automatically repaired. This is an app-private integrity boundary,
not resistance to a compromised Android OS or hardware-backed rollback proof.

The binding remains policy-only: lifecycle-bearing checkpoints are rejected before
recovery commits can consume outcomes. Request delivery must later extend this
same owner with durable effect dispatch instead of making another inbox.

Shutdown separates dropping Rust state from completing OS notification cleanup.
A failed clear leaves an explicit downward cleanup obligation. Kotlin retains the
native handle and worker for explicit retry; Activity close/rotation does not shut
down the owner. A response timeout does not turn a late write into a reported save.

## Packaging and validation boundaries

Both libcontroller_app_lib.so and libuac_android_controller.so are required in the
same arm64 APK, alongside JNA. Gradle task dependencies include actual ABI-flavored
compile/merge task names. No APK ABI is advertised without both components.
Extracted package libraries are used so JNA needs no writable cache fallback.
[Android packaging guidance](https://developer.android.com/guide/practices/page-sizes)
does not itself prove this APK's loading or 16-KB compatibility; inspect the built
artifact and exercise the device separately.

The Gradle build uses Kotlin 2.2.21 with Gradle 8.14.3 and AGP 8.11.0, inside the
published [Kotlin/Gradle compatibility range](https://kotlinlang.org/docs/gradle-configure-project.html).
The earlier isolated Kotlin 1.9.25 compilation is only source/ABI evidence, not
proof of this complete Android dependency graph. Compiler warnings remain errors.

ROOT compiles and tests. The Kotlin worker and security auditor do not execute
validation. The user will later perform actual UAC approval and phone-authentication
acceptance; browser galleries, unit tests and an APK build do not replace those.
