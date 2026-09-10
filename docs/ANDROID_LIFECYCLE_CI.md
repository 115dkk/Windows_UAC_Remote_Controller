# Real-product Android lifecycle CI

Status: implemented_unverified. Source authored without child execution; ROOT runs the checks and CI. This is not the notification-gallery APK and is not a full G009, enrollment, remote-UAC, first-unlock, or hardware-authentication proof.

## Fixed scope

The workflow builds the genuine debuggable `dev.dkk115.uacremote` APK, including Tauri and the real Rust controller/JNA libraries, for API36 `google_apis` x86_64. Its separate AndroidJUnitRunner APK targets that product. No substitute actor, authentication result, key, enrollment, incoming request or signing bridge is installed. The disposable emulator is initially unlocked without a configured credential; locked-first-boot/FBE and physical authentication remain pending.

`node tools/android-lifecycle-ci.mjs --prepare` records exact tracked source hashes before APK construction and refuses existing APK outputs. The no-argument invocation accepts only Linux GitHub Actions, Node24, the exact Actions checkout, the sole `emulator-5554`, and the fixed `uac-lifecycle-ci-36-x86_64` AVD. It verifies SDK/ABI/emulator facts before device mutations. There are no caller-selected packages, paths or devices and no local-device fallback. The APK inspector verifies actual x86_64 libraries; decoded merged manifests bind both packages, real Application/receiver/FGS and instrumentation target. Installed APK hashes are independently computed inside the actual native test and compared with a fresh phase nonce.

## Sequence and evidence

1. Fresh install and an actual framework broadcast/application barrier; no warm-up launch or delay substitutes for this barrier.
2. `initial` instrumentation launches the actual MainActivity, observes the real native owner READY and fixed foreground notification, recreates the Activity and repeats start while retaining the same in-process actor. It explicitly stops, waits for native CLOSED plus disabled boot receiver, relaunches without re-enabling, and explicitly starts a replacement only after old closure.
3. A declared ordinary Activity launch establishes the non-instrumented enabled baseline; HOME leaves the service in the background.
4. Actual emulator reboot changes `/proc/sys/kernel/random/boot_id`. The host reads OS foreground-service state and passive native diagnostics **before any Activity launch or instrumentation**. It then performs a real `adb install -r` of the same exact APK and repeats those pre-launch observations. This is an actual same-version package-replacement path, not a version migration or synthetic broadcast.
5. `stop` instrumentation performs the existing native explicit-stop action and requires actual CLOSED/DISABLED. Ordinary reopen stays off. Another actual reboot and package replacement are observed while disabled, before launch; subsequent `verify-stopped` tests check persistent component state. `start` explicitly re-enables and waits for READY again.

`am instrument` can restart/terminate its target process. Its after-launch observations are **never** used as evidence that a boot/update receiver started the app. Host pre-launch observations establish only the measured state; checking no resumed target Activity is not a claim that every possible historical UI event was traced.

The passive diagnostic adds only existing framework `Service.dump` output: 14 bounded enum/boolean fields, main-thread only. It ignores arguments, accesses no requests/keys/CE files, creates no native owner, and does not wait on the worker. The Application helper reads already-existing lifecycle fields. There is no new intent, renderer command, privileged permission, authentication flag or test-authority API. Same-owner comparison uses read-only reflection solely inside instrumentation; no identity is serialized.

## Bounds and failure

- Each native state wait is at most30s; one instrumentation process at most180s; host readiness45s; reconnect/boot waits90s each. These do not alter product deadlines.
- Existing `runProver` is reused only for its bounded local child/process-group/output lifetime (not proof verdict parsing). Typical command output512KiB; instrumentation2MiB. No more than400 host commands, output-tree512 entries/depth8, APK256MiB.
- SIGINT/SIGTERM abort the owned local command. Killing a local adb client is **not** proof that Android work stopped. A failed/uncertain mutation latches `deviceOperationMayContinue`; no further mutation, retry or automatic app-data cleanup occurs. The emulator action owns its disposable emulator lifetime.
- No `pm clear`, force-stop, uninstall, credential/PIN configuration, simulated locked boot or privileged product policy changes. Evidence directories and failure artifacts are retained, not deleted. Missing/duplicate/stale receipts, zero tests, failed process cleanup and unavailable native dumps fail the run.
- `source-input` preparation is explicitly `SOURCE_INPUTS_ONLY` with lifecycle `passed:false`. Only the complete native sequence may set the run's lifecycle `passed:true`. That narrow result still has `firstUnlockVerified:false`, `physicalAuthenticationVerified:false`, `requestDeliveryVerified:false`.

## ROOT validation entry points

- `node --test tools/android-lifecycle-ci.test.mjs` (11 synthetic host guard/parser tests; no Android proof).
- Workflow also runs the existing ABI/build/APK/manifest tests and two **actual Gradle configuration** rejection cases. They follow the genuine build so Tauri's ignored machine-local Gradle settings exist. Nonzero alone is insufficient: the exact expected ABI selector error must be present and local process cleanup complete.
- `ORG_GRADLE_PROJECT_controllerAbi=x86_64 npm run tauri -- android build --debug --target x86_64 --apk --ci`.
- `:app:assembleUniversalDebugAndroidTest -PabiList=x86_64 -ParchList=x86_64 -PtargetList=x86_64` using the same `controllerAbi` environment.
- Workflow `.github/workflows/android-lifecycle.yml` runs the fixed CI-only helper. Inspect every native phase receipt, APK hashes, actual reboot IDs and pre-launch service logs; do not substitute the independent renderer gallery.

Framework references: Android16 [Service.dump contract](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-16.0.0_r1/core/java/android/app/Service.java), [ActivityThread main-handler dispatch](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-16.0.0_r1/core/java/android/app/ActivityThread.java), and [ServiceRecord foreground metadata](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-16.0.0_r1/services/core/java/com/android/server/am/ServiceRecord.java). [Direct Boot](https://developer.android.com/privacy-and-security/direct-boot) requires a separately scoped first-unlock test; this workflow does not configure or emulate credentials.
