# Android notification renderer gallery

This independent **test-only APK** compiles the exact product
`RequestNotificationRenderer.kt` and its resources. It has a different application
ID, ordinary Application/Activity, no Internet permission, no service/receiver,
no Rust/JNA component, no enrolled peer, no credential and no approval handler.
Its three PendingIntents reopen this gallery only. Never ship it as the product.

The CI job runs it on a disposable x86_64 Android36 emulator. The actual product
remains an ARM64 APK and is built/tested by Android package. Native renderer PNGs
are not physical-phone, authentication, latency or end-to-end UAC evidence.
The controller body originates from synthetic PowerShell display strings only.

The runner refuses non-GitHub environments and any physical/multiple device
configuration. It captures real emulator screenshots/UI XML, native field-check
receipts and exact source/APK hashes. ROOT must inspect captures; an exit0 is not
a visual approval. Sound/vibration delivery cannot be inferred from screenshots.

Build on CI with the existing checked-in Gradle8.14.3 wrapper:
`bash src-tauri/gen/android/gradlew -p tools/android-notification-gallery assembleDebug --no-daemon`.
Do not install an emulator/SDK on the space-constrained development machine.
