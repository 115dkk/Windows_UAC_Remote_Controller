# Android Application policy owner

SPDX-License-Identifier: GPL-2.0-or-later

This is **policy-only Application wiring, not a working background approval service**.
ControllerApplication owns one bounded worker and this generated controller. The
Android Tauri shell no longer opens AppRuntime; it reads/saves policy through the
Application plugin. Windows retains its existing runtime. Native arm64 Rust,
generated Kotlin/Application code and the Android Tauri Rust shell compile. Actual
Gradle/APK and device evidence must still be checked separately.

ABI version 2 exposes openOrInitialize and recovery-only openExisting, not an
unguarded fresh constructor. Application startup adopts existing state; fresh
initialization requires an empty private directory, no controller key aliases,
strictly readable old preferences and an exclusive first-attempt marker. A marker
or any state/intent/staging/lock file prevents another fresh attempt. A corrupt or
missing snapshot after an earlier attempt is not reset. Old preferences are read
from Android dataDir (Tauri's actual resolver), not filesDir, and are not deleted.
The marker is not a secret, hardware rollback counter or power-loss guarantee.

The handwritten Rust boundary forbids unsafe code and uses pinned UniFFI0.32
generation. Generated/dependency ABI machinery is not claimed unsafe-free.
NativePlatform provides Application-owned directory/clock observations and
downward-only request-notification cleanup. There is no generic wire ingress,
key alias, signature, approval boolean, execution or renderer path parameter.

MobileController's process-local ownership lease is acquired before callbacks
and held until the generated object is destroyed. Its separate operation lease
rejects concurrent/reentrant work before taking the state mutex. Foreign callbacks
run outside that mutex. Native storage's OS writer lock is still required; this
static alone is not an across-process/across-library singleton.

Call shutdownNativeOwner() and then the generated close()/destroy() when the
native owner is actually being stopped. Generated close() frees the ABI object;
it is not the Rust shutdown operation. The first generated Kotlin compile caught
a reserved close() collision; the Rust operation was renamed and regenerated.
Do not tie owner shutdown to an Activity merely closing or rotating.
If native cleanup fails, keep the handle and retry shutdown explicitly before
destroying it. Dropping the inbox is not proof that notifications were withdrawn.

Native constructors require directory-synchronized storage and never use host
test factories. Fresh creation is explicit and is not recovery from a failed open.
The temporary policy-only preflight keeps the same writer lock while refusing
request/source/fault-bearing checkpoints BEFORE recovery can commit and consume
outcome effects. Full lifecycle startup must use the full DurableInbox path and
a real dispatcher/outcome recovery mechanism; refusal is not the final design.

The native platform implementation and constructor choices are trusted app code,
not security tokens. The loader rejects loading overrides before using generated
code and confines JNA to extracted package-owned libraries; it has no cache or
download fallback. Startup cleanup occurs only after owning the actual store.
Gradle declares the matching native-library staging and arm64-only APK variants.
Source declarations/isolated compiles do not prove packaged loading or OS cleanup.

Build/generate: `node tools/build-android-bindings.mjs --abi arm64-v8a --variant debug`.
The script uses the installed pinned NDK and host-only generator. Gradle source
generation and JNA5.19.1 AAR dependency are declared; full Gradle/APK execution,
release shrinking, Android16KiB-page/device behavior and Kotlin/JNA runtime calls
remain unverified. No library-copy/symlink workaround was used for the existing
blocked Tauri APK packaging path.
