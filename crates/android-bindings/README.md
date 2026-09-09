# Android Application policy owner

SPDX-License-Identifier: GPL-2.0-or-later

This is **policy-only Application wiring, not a working background approval service**.
ControllerApplication owns one bounded worker and this generated controller. The
Android Tauri shell no longer opens AppRuntime; it reads/saves policy through the
Application plugin. Windows retains its existing runtime. Native arm64 Rust,
generated Kotlin/Application code, Gradle/APK and device evidence are separate
gates; compilation is not a native key or authentication result.

ABI version 7 retains openOrInitialize and recovery-only openExisting, not an
unguarded fresh constructor. Application startup adopts existing state; fresh
initialization requires an empty private directory, no controller key aliases,
strictly readable old preferences and an exclusive first-attempt marker. A marker
or any state/intent/staging/lock file prevents another fresh attempt. A corrupt or
missing snapshot after an earlier attempt is not reset. Old preferences are read
from Android dataDir (Tauri's actual resolver), not filesDir, and are not deleted.
The marker is not a secret, hardware rollback counter or power-loss guarantee.
History read/clear from ABI3 remains. ABI4 adds only outbound native descriptors
and read-only key reopen/memory-reference release callbacks, not generation or
enrollment commands. [ADR0008](../../docs/adr/0008-phone-local-key-lifecycle.md)
describes V2 checkpoint metadata, store-locked preflight and failure ownership.

ABI5 adds opaque original-request approval plans, one-shot signing claims and
prepared submissions, plus downward exact-request withdrawal. It still exposes
no generic signer, raw decision wire sender, enrollment setter or working Tauri
approval action. The existing Application worker and DeviceKeyStore now contain
the API30+ per-use CryptoObject lifecycle. A prepared submission is NOT sent or
Windows-approved. The policy-only startup gate remains until real enrolled
intake, full notification/effect delivery and outgoing transport are connected.
See [ADR0011](../../docs/adr/0011-native-approval-operation.md) for lifetime,
cancellation, cleanup and explicitly deferred native acceptance.

ABI6 adds opaque Client CertificateVerify inputs and original-association native
transport bindings. A native Rust composition factory uses the existing Android
TRANSPORT reference; it is not an exported dialer, enrollment command or arbitrary
signer. Key/association withdrawal closes the binding, and native teardown retains
bounded partial cleanup. [ADR0012](../../docs/adr/0012-bound-native-transport-and-send.md)
describes this factory and the real guarded approval-write path. Application
connection provisioning, foreground intake and PC service action wiring remain.

ABI7 adds opaque request-scoped denial scopes and one-shot attempts. Rust retains
the approval fence and private prepared denial; Kotlin uses only the exact existing
DENIAL key without approval authentication. Native approval-session cleanup and
the matching Rust native slot are checked independently before signing. Cancellation
continues to reach the original attempt after native retirement. There is no
exported denial submission or signed-wire getter, and no connected transport is
invented for this prepared-unsent boundary. See [ADR0014](../../docs/adr/0014-native-denial-fence-and-cleanup.md).

Stop retains logically closed core owners until native retirement and reference
cleanup complete. Ordinary `continueNativeCleanup()` preserves failed cleanup
steps; explicit `shutdownNativeOwner()` or scoped `retryDenialCleanup()` may retry
the original failed step once. Neither can rearm a cancelled scope or sign again.

The handwritten Rust boundary forbids unsafe code and uses pinned UniFFI0.32
generation. Generated/dependency ABI machinery is not claimed unsafe-free.
NativePlatform provides Application-owned directory/clock observations, exact
native cleanup observations and downward request-notification/key-reference cleanup.
Bounded signature bytes are input only to finishing the original opaque attempt;
there is no generic wire ingress, caller-selected key alias, authentication boolean,
execution or renderer path parameter.

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
The Application also retains its native platform adapter when construction fails
after partial reopening; memory-only reference cleanup then has an explicit retry
path even without a returned Rust handle. Aliases and checkpoint data remain.

Native constructors require directory-synchronized storage and never use host
test factories. Fresh creation is explicit and is not recovery from a failed open.
The temporary policy-only preflight keeps the same writer lock while refusing
request/source/fault-bearing checkpoints BEFORE recovery can commit and consume
outcome effects. Under that same lock, empty metadata with surviving aliases or
Preparing key state rejects before any migration/write. CreatedUnverified metadata
only reopens exact native keys; it is not an enrolled peer. The last initialization
clock sample is retained as the next native-observation floor. Full lifecycle
startup must use the full DurableInbox path and
a real dispatcher/outcome recovery mechanism; refusal is not the final design.

The native platform implementation and constructor choices are trusted app code,
not security tokens. The loader rejects loading overrides before using generated
code and confines JNA to extracted package-owned libraries; it has no cache or
download fallback. Startup cleanup occurs only after owning the actual store.
Gradle declares the matching native-library staging and arm64-only APK variants.
Source declarations/isolated compiles do not prove packaged loading or OS cleanup.

Build/generate: `node tools/build-android-bindings.mjs --abi arm64-v8a --variant debug`.
The script uses the installed pinned NDK and host-only generator. Gradle source
generation and JNA5.19.1 AAR dependency are declared. Earlier ABI3 full APK builds
passed in hosted CI, as did ABI4 source5747d58, ABI5 sourceaba127f and ABI6 sourceb5b3b19.
ABI7 requires its own exact-source generated Kotlin/Gradle run. Release shrinking,
Android16KiB-page/device behavior and Kotlin/JNA runtime calls remain separate
unverified gates. No library-copy/symlink permission workaround is used.
