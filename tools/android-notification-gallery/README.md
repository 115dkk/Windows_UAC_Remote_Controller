# Android notification renderer gallery

This independent **test-only APK** compiles the exact product
`RequestNotificationRenderer.kt`, `ControllerStatusNotificationRenderer.kt` and
their resources. Existing lightweight `BootServicePolicy.kt`/`PolicyOwnerRules.kt`
provide the real `ControllerServiceState` type without including its service or
native owner. It has a different application
ID, ordinary Application/Activity, no Internet permission, no service/receiver,
no Rust/JNA component, no enrolled peer, no credential and no approval handler.
Its request PendingIntents and status content intent reopen this gallery only.
Never ship it as the product.

The original five cases remain `sound`, `vibration`, `silent`, `restore`, and
`withdrawn`. Added cases are `status-preparing`, `status-ready`, and
`status-stopping`. Status-ready is LOCAL_SETTINGS_READY, not connected/remote
approval readiness. These cases call the exact production status builder and
ordinary `NotificationManager.notify`; they do **not** call `startForeground`,
start a service, simulate a boot callback or prove foreground-service lifetime.
Status notifications have no approval/denial/detail actions. Native field checks
cover the fixed ID/channel, quiet low-importance channel settings, title/body,
ongoing/local-only/only-alert-once flags, hidden timestamp and no full-screen or
timeout. System-shade XML must show the exact current resource title and body,
with no request actions; ROOT still reviews the actual screenshot pixels.

The CI job runs it on a disposable x86_64 Android36 emulator. The actual product
remains an ARM64 APK and is built/tested by Android package. Native renderer PNGs
are not physical-phone, authentication, latency or end-to-end UAC evidence.
Request bodies originate from the unchanged synthetic PowerShell display strings.
Status text comes from the actual product string resources and preserves the
production state-to-resource mappings; it is not a handwritten gallery renderer.

The runner refuses non-GitHub environments and any physical/multiple device
configuration. It captures real emulator screenshots/UI XML, native field-check
receipts and exact source/APK hashes. Gradle copies only the listed shared inputs,
checks copied bytes against product files and packages a bounded hash receipt.
The Activity reads that actual APK asset; the runner requires all twelve hashes
to match current renderer/policy/resource files and rechecks inputs after capture.
The production service callsite hash is recorded separately and explicitly is
not compiled into the gallery APK. This binds rendering evidence, not runtime
ownership or native authorization. ROOT must inspect captures; an exit0 is not
a visual approval. Sound/vibration delivery cannot be inferred from screenshots.

Build on CI with the existing checked-in Gradle8.14.3 wrapper:
`bash src-tauri/gen/android/gradlew -p tools/android-notification-gallery assembleDebug --no-daemon`.
Do not install an emulator/SDK on the space-constrained development machine.
