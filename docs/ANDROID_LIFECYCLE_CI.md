# Real-product Android lifecycle CI

Status: first_unlock_extension_implemented_unverified. ROOT verified the earlier c4bd native run34514602784: all five original phases, eight observations and272 command-log hashes passed. The appended first-unlock sequence below has not run. Source authors do not execute validation. This is not the notification-gallery APK or a full G009, enrollment, remote-UAC or hardware-authentication proof.

The first actual4689319 emulator run reached READY, retained the same owner after
Activity recreation/repeated start, then timed out waiting for explicit stop to
reach CLOSED/STOPPED with its notification removed. Source review found the final
Rust I/O completion wake was routed into an already-stopped request coordinator.
The fix routes STOPPING/FAILED completion into existing cleanup-only continuation;
failed native-wrapper destruction still needs explicit retry. Three JVM regression
cases and bounded timeout/failure diagnostics were added. The later c4bd run
established that original lifecycle sequence; it did not establish first unlock.

Android-only implicit Tauri exit is now prevented so finishing the last Activity
does not terminate the shared foreground-service process. Explicit exit/restart
and desktop behavior are unchanged. The native test also requires the actual
attached WebView to render the local Korean application shell on launch,
recreation and close/relaunch; an actor READY observation or blank window cannot
satisfy this check. These original lifecycle assertions passed in the c4bd run;
the new first-unlock assertions require their own exact-source run.

The dependency patch provides explicit original-Activity leases and
physical WebView origin propagation. The initial native test additionally uses
the same real current STOP envelope with retired/current JNI WebView objects,
requiring rejection versus actual STOP/CLOSED and restart. A separate parameterless
READ pair exercises the native custom-protocol entry with the same current
headers and retired/current objects; it is not a framework-generated fetch test.
Payloads and invocation keys remain test-process memory only. Any native-entry
timeout records unconfirmed device work and stops the host's operation sequence.
Tracked vendor source is part of the immutable prebuild/after-build snapshot.

## Fixed scope

The workflow builds the genuine debuggable `dev.dkk115.uacremote` APK, including Tauri and the real Rust controller/JNA libraries, for API36 `google_apis` x86_64. Its separate AndroidJUnitRunner APK targets that product. No substitute actor, authentication result, key, enrollment, incoming request or signing bridge is installed. Only after the original scenarios finish, an actual native KeyguardManager check must establish that no secure lock exists. The extension then sets the fixed public synthetic CI PIN `4938` on this disposable AVD. This value is test data, never a personal credential. It is retained until AVD teardown, not cleared as cleanup. Physical-phone authentication and Keystore/BiometricPrompt acceptance remain separate and unverified.

`node tools/android-lifecycle-ci.mjs --prepare` records exact tracked source hashes before APK construction and refuses existing APK outputs. The no-argument invocation accepts only Linux GitHub Actions, Node24, the exact Actions checkout, the sole `emulator-5554`, and the fixed `uac-lifecycle-ci-36-x86_64` AVD. It verifies SDK/ABI/emulator facts before device mutations. There are no caller-selected packages, paths or devices and no local-device fallback. The APK inspector verifies actual x86_64 libraries; decoded merged manifests bind both packages, real Application/receiver/FGS and instrumentation target. Installed APK hashes are independently computed inside the actual native test and compared with a fresh phase nonce.

## Sequence and evidence

1. Fresh install and an actual framework broadcast/application barrier; no warm-up launch or delay substitutes for this barrier.
2. `initial` instrumentation launches the actual MainActivity, observes the real native owner READY and fixed foreground notification, recreates the Activity and repeats start while retaining the same in-process actor. It explicitly stops, waits for native CLOSED plus disabled boot receiver, relaunches without re-enabling, and explicitly starts a replacement only after old closure.
3. A declared ordinary Activity launch establishes the non-instrumented enabled baseline; HOME leaves the service in the background.
4. Actual emulator reboot changes `/proc/sys/kernel/random/boot_id`. The host reads OS foreground-service state and passive native diagnostics **before any Activity launch or instrumentation**. It then performs a real `adb install -r` of the same exact APK and repeats those pre-launch observations. This is an actual same-version package-replacement path, not a version migration or synthetic broadcast.
5. `stop` instrumentation performs the existing native explicit-stop action and requires actual CLOSED/DISABLED. Ordinary reopen stays off. Another actual reboot and package replacement are observed while disabled, before launch; subsequent `verify-stopped` tests check persistent component state. `start` explicitly re-enables and waits for READY again.
6. Only after `explicit-restart-ready`, `verify-no-secure-lock` checks real `KeyguardManager.isDeviceSecure()` before and after its normal Activity observation. Both must be false, and the user must be unlocked. Host guards additionally require user0 and `ro.crypto.type=file`. A single supported `locksettings set-pin --user 0` call configures only the fixed synthetic fixture; no old credential is supplied or guessed.
7. Another actual reboot must change the kernel boot identity. Before any target Activity or instrumentation in that boot, three separately timed observations require framework `RUNNING_LOCKED`, the exact OS foreground service, and passive `WAITING_FOR_UNLOCK`, `owner_present=false`, `owner_phase=NONE`, with no pending/uncertain construction. No unlock-dependent broadcast barrier runs during this locked phase. These observations establish no native actor and a locked CE user state, not an exhaustive filesystem-access audit.
8. Ordinary wake/input events operate only on a freshly recognized SystemUI layout. The closed helper admits AOSP16's source-defined classic PIN controls and, optionally, one reveal swipe derived from its recognized keyguard container. Every digit and submit tap uses a new hierarchy and derived bounds; snapshot age is checked after the device guard immediately before dispatch and must be at most5s. Four digits and one submit are the only credential attempt. Unknown/Compose-only layouts, malformed/ambiguous controls or failed hierarchy capture stop the run before further input; there is no fallback unlock mechanism.
9. In the same boot, framework `RUNNING_UNLOCKED` and the full passive READY predicate must be observed before launching the product. Only then may `verify-first-unlock` instrumentation run; actual native secure-lock checks must remain true and boot count must advance exactly once. Normal source/APK/nonces/process-cleanup gates still apply before success.

`am instrument` can restart/terminate its target process. Its after-launch observations are **never** used as evidence that a boot/update receiver started the app. Host pre-launch observations establish only the measured state; checking no resumed target Activity is not a claim that every possible historical UI event was traced.

The passive diagnostic adds only existing framework `Service.dump` output: 14 bounded enum/boolean fields, main-thread only. It ignores arguments, accesses no requests/keys/CE files, creates no native owner, and does not wait on the worker. The Application helper reads already-existing lifecycle fields. There is no new intent, renderer command, privileged permission, authentication flag or test-authority API. Same-owner comparison uses read-only reflection solely inside instrumentation; no identity is serialized.

## Bounds and failure

- Each native state wait is at most30s; one instrumentation process at most180s; host readiness45s; reconnect/boot waits90s each. These do not alter product deadlines.
- First-unlock observation permits at most10 samples within45s; its two additional stable locked samples each have15s. SystemUI interaction has a120s overall deadline, at most one reveal and five PIN-control taps, and no retry/credential guessing. Capture commands are15s maximum and XML is256KiB maximum,256 nodes/depth32. XML uses fresh nonce/index paths only under `/data/local/tmp`, never CE or `/sdcard`; zero exit without the exact file receipt and fresh valid XML is not success. Retained files disappear only with disposable-AVD teardown.
- Existing `runProver` is reused only for its bounded local child/process-group/output lifetime (not proof verdict parsing). Typical command output512KiB; instrumentation2MiB. The original sequence retains its400-command ceiling. Only after it finishes does the first-unlock extension receive at most512 additional commands, including32 reserved for read-only failure diagnostics, with an absolute912-command ceiling. The nominal optional-reveal path uses223 commands; bounded boot polls and owner-observation retries fit inside480 operational commands. APK output-tree512 entries/depth8 and APK256MiB limits remain.
- SIGINT/SIGTERM abort the owned local command. Killing a local adb client is **not** proof that Android work stopped. A failed/uncertain mutation latches `deviceOperationMayContinue`; no further mutation, retry or automatic app-data cleanup occurs. The emulator action owns its disposable emulator lifetime.
- No `pm clear`, force-stop, uninstall, `adb root`, credential verification/clearing shell command, direct CE/user unlock, emulated FBE or disabled security policy. The sole credential-setting exception is the fixed synthetic fixture above after an actual no-existing-secure-lock check. Evidence directories and failure artifacts are retained, not deleted. Missing/duplicate/stale receipts, zero tests, failed process cleanup and unavailable native dumps fail the run.
- `source-input` preparation is explicitly `SOURCE_INPUTS_ONLY` with lifecycle `passed:false`. Only the full original-plus-first-unlock sequence may set `REAL_PRODUCT_EMULATOR_LIFECYCLE_AND_FIRST_UNLOCK` to `passed:true` and `firstUnlockVerified:true`. Failure/cancellation/uncertain cleanup clears first-unlock success. `physicalAuthenticationVerified:false` and `requestDeliveryVerified:false` remain unchanged; this is ordinary OS credential UI on an owned emulator, not physical-phone approval authentication.

## ROOT validation entry points

- `node --test tools/android-lifecycle-ci.test.mjs` (synthetic host/parser/first-unlock evidence tests; no Android proof).
- Workflow also runs the existing ABI/build/APK/manifest tests and two **actual Gradle configuration** rejection cases. They follow the genuine build so Tauri's ignored machine-local Gradle settings exist. Nonzero alone is insufficient: the exact expected ABI selector error must be present and local process cleanup complete.
- `ORG_GRADLE_PROJECT_controllerAbi=x86_64 npm run tauri -- android build --debug --target x86_64 --apk --ci`.
- `:app:assembleUniversalDebugAndroidTest -PabiList=x86_64 -ParchList=x86_64 -PtargetList=x86_64` using the same `controllerAbi` environment. The mandatory preceding Tauri CLI step builds the real product. The instrumentation step first checks its APK/ELF and exact Tauri-library hash, then reuses that library with only the redundant `:app:rustBuildX86_64Debug` callback excluded; its CLI WebSocket has already closed. Actual instrumentation compilation/packaging still runs, and both original APK and library hashes must remain unchanged afterward.
- Workflow `.github/workflows/android-lifecycle.yml` runs the fixed CI-only helper. Inspect every native phase receipt, APK hashes, actual reboot IDs and pre-launch service logs; do not substitute the independent renderer gallery.

Framework references: Android16 [Service.dump contract](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-16.0.0_r1/core/java/android/app/Service.java), [ActivityThread main-handler dispatch](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-16.0.0_r1/core/java/android/app/ActivityThread.java), and [ServiceRecord foreground metadata](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-16.0.0_r1/services/core/java/com/android/server/am/ServiceRecord.java).

The bounded first-unlock extension follows [Direct Boot storage/unlock semantics](https://developer.android.com/privacy-and-security/direct-boot), Android16's [shell credential setup](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-16.0.0_r1/services/core/java/com/android/server/locksettings/LockSettingsShellCommand.java), [ordinary input events](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-16.0.0_r1/services/core/java/com/android/server/input/InputShellCommand.java), [hierarchy dump command](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-16.0.0_r1/cmds/uiautomator/cmds/uiautomator/src/com/android/commands/uiautomator/DumpCommand.java), and [source-defined PIN layout](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-16.0.0_r1/packages/SystemUI/res-keyguard/layout/keyguard_pin_view.xml). These references are not a claim that the downloaded CI image has already exposed that layout; its first actual hierarchy must qualify it or the test fails closed.
