# Development handoff — 2026-09-11

This inventory prevents duplicate implementation. It is not a readiness claim.
Last checked implementation revision: `5534d1683838b8e6072890fe16b4422b3dfda7a2` on
`codex/native-runtime`. This document separates that baseline, installed native
experiments and unmerged protocol experiments. New edits require new ROOT checks.

## Latest evidence — September 11

At5534d16, complete Windows/Linux/Android Rust quality, actual Analyzer/canaries,
both app packages, notification rendering and fixed Google attestation-status
interoperability passed. The exact Windows tests include ordinary-process
endpoint rejection, actual fixed-size token queries and the corrected bounded-SID
fixture. Canonical QR invitation and phone frozen-candidate tests are included.

Actual Android lifecycle failed twice after stop and immediate real reboot:
d45b6ac and5534d16 each observed a newly running foreground/READY owner with the
old boot component ENABLED. The latter reached the observation timeout, while
the earlier run also had a genuine global application-barrier give-up. The
previous passing65f9883 lifecycle below does not resolve this observed regression.
ROOT retained/hash-checked223 and306 command logs respectively. First unlock was
not reached in either failed sequence.

The new repair uses a fixed private device-protected ON/OFF record and one
Application-owned asynchronous registration operation. A stable manifest-enabled
wake receiver is never toggled; the old component is filterless for migration.
The persistence, callback and lifecycle source plus matching host evidence guards
are authored and statically reviewed; corrected native behavior awaits new CI.
This is not a published release or a new local UAC/provider experiment.

The following65f9883 checkpoint is historical and retains its original scope.

At65f9883, all five CI workflows passed. Full host/Android quality, both packages,
notification rendering and the genuine unlocked-emulator lifecycle are green.
[Actual lifecycle34529268532](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34529268532)
completed seven instrumentation phases and twelve host observations: document
load/recreation/close-relaunch, exact current-versus-retired IPC, enabled reboot
and package update before app launch, explicit stop, disabled reopen/reboot/update,
and explicit restart. A subsequent real file-based-encryption reboot remained
locked with a foreground notification and WAITING_FOR_UNLOCK but no native owner.
Ordinary System UI entry of a public synthetic CI PIN then produced full READY
on that same boot before any target Activity/instrumentation launch. ROOT retained
and hash-checked all529 command logs, reparsed seven instrumentation receipts,
and checked six actual System UI hierarchies/tap coordinates. APKs were not
downloaded again; bounded log extraction kept the ZIP only in memory.

The earlier cold-plugin initialization and premature notification assertion no
longer prevent this full sequence. Emulator first unlock is now observed;
physical-phone authentication, provisioning/pairing, real network delivery and
Windows UAC application remain unverified. A passing build/lifecycle is not a
release or a finished remote approval product.

The corrected5137e76 Windows diagnostic was independently authorized for exactly
one further attempt. ROOT verified its exact CI artifact and announced UAC before
launch at05:46:10KST onSeptember11. Windows returned user cancellation; no
bootstrap/provider observation was obtained. At05:48:50 the temporary service,
process, installation and result directories were absent. That one-shot permission
is consumed. Production service/key/security policy were unchanged.

The65f9883 source separates early SCM Running from actual initialization, adds a
one-use running acknowledgement before platform-key calls, and keeps the original
deadline through Ready. Product status remains StartPending until both readiness
controls are present. A distinct signed frozen-candidate codec binds the original
pairing context and three role-labelled phone keys before exposing a comparison
code. These changes passed full Windows/Linux quality, including actual Analyzer
and its canaries. Linux logs explicitly include all14 frozen-codec cases and16
portable startup-phase cases. They are neither a TPM fix nor completed native
pairing. New native pipe-peer authentication, bounded server I/O and Android
frozen-candidate owner integration are separate source slices awaiting fresh CI.

The checkpoints below are historical; the65f9883 result above is the current
completed lifecycle/first-unlock and quality baseline.

At0713333 the full Quality run34510391762 passed: Windows15m00, Linux8m54,
protocol6m48, Android Rust/core3m22. Both actual Analyzer scans reported zero
errors/warnings and their real clean/error/warning canaries passed. Windows
package34510391766, Android APK/Kotlin34510391776 and renderer34510391729 passed.

Genuine lifecycle34510391633 passed initial document/recreate/relaunch and both
physical-origin IPC comparisons; enabled actual reboot and package replacement
each produced a READY native owner before Activity/instrumentation. Explicit stop
closed the owner and removed its notification. Manual reopen and a second actual
reboot preserved DISABLED/absence. The next verify-stopped cold Activity launch
crashed during Tauri's built-in app-plugin initialization with a disconnected
reply channel. Thus the final disabled-update/restart phases remain unverified.
The active-service parser fix passed those earlier observations; it was not this
run's failure. A narrow Wry queue-metadata contention fix is being reviewed.

The following9e8e37f and85354bf checkpoints are historical and retain their exact
scope; their Analyzer failures are resolved by0713333 above.

The vendored SDK changes have now compiled in actual Android product APKs and
Windows packages. At85354bf and9e8e37f, real Android instrumentation passed initial
document load, Activity recreation, close/relaunch, explicit stop/restart, and
both retired-versus-current physical-view IPC comparisons. Each initial phase
ran one real instrumentation test with every required receipt fact true.

At9e8e37f, actual reboot delivered LOCKED_BOOT_COMPLETED and BOOT_COMPLETED,
promoted the private foreground component and created a READY native owner before
any post-reboot Activity/instrumentation. The host test then rejected a global
historical ANR record for Android System UI, despite the target's active service
record being valid. The parser needs to distinguish historical and active user
sections, then rerun the full sequence. This partial observation is not a passing
whole reboot/update lifecycle run. The earlier85354bf reboot timeout had no
active target service at capture; its exact cause remains unestablished.

At9e8e37f, all Rust tests/Clippy and the16-obligation protocol job passed. Linux
and Windows Quality remained red on actual Analyzer diagnostics in newly
vendored upstream code (15 and14 respectively). Source fixes are in progress;
the warning/error gate is unchanged. Windows packaging, ARM64 APK/Kotlin and
notification rendering passed. No additional Windows elevation has run.

The following older checkpoints are historical; their pending SDK/protocol work
has been superseded by the evidence above and the01ab810 formal result below.

At01ab810 the entire Quality run34501026437 passed: protocol6m51, Linux9m17,
Windows15m48 and Androidcore2m55. All16 original protocol obligations passed,
including fresh three-witness file-only checks/integrity controls and both
source-derived attack-existence canaries with original-model no-trace controls.
ROOT downloaded and reparsed all actual transcripts/derived inputs against
current bound source and recorded Superloopy G009/C002 passing evidence.
This proves the stated symbolic models, not native key isolation or UAC/auth.
Windows package34501026430 passed10m32; Android package34501026469 and renderer
34501026426 passed. Lifecycle34501026502 still failed11m19; the pending SDK fixes
are not included in01ab810.

September11 continuation: e5f1cf6 host Rust, Android core/APK/Kotlin, Windows
package and notification renderer checks passed. Its normal protocol run retained
all16 obligations and successfully discharged the approve/deny witnesses with
fresh good/sorry/contradiction checks. Six request-safety properties and channel
checks passed; two-approver and both request canaries still timed out there.
Isolated b018f20 experiments subsequently verified the stronger two-approver
witness, both intentionally broken-model attacks, and absence of those attacks
in the original models. Remaining normal integration is in progress.

Actual e423727 lifecycle evidence established initial/recreated documents,
same-owner retention and explicit native STOP/CLOSED with notification removal.
It then failed because close/relaunch produced no attached WebView. Targeted
same-version Tao/Tauri/Wry changes now implement exact Activity attachment and
physical-origin IPC, with immutable Kotlin adapters and actual stale-view/current-
view test pairs. These dependency changes are not yet compiled or native-verified.
They must not be confused with the passing e5f1cf6 packaging baseline.

At `4689319d5c503d0fb3391c66c97bcd3eadb5fe7d`, ROOT collected completed native
CI watchers: Windows package (34487343380), ARM64 APK/Kotlin tests
(34487343330), notification renderer (34487343387), and Windows/Linux/Android
Rust jobs (34487343352) passed. The overall Quality run still failed its normal
protocol job: three honest request witnesses and two request canaries timed out.

The genuine x86_64 lifecycle run (34487343364) built and installed both product
and instrumentation APKs, reached READY and retained the owner across Activity
recreation/repeated start, then failed waiting for explicit stop to finish. The
shutdown completion wake routing fix and further Activity-lifetime work are in
progress. Native reboot/update and close/relaunch acceptance remain unverified.

The corrected isolated Windows context source is now `5137e76`; build and
ordinary-privilege read-only guard checks passed. The failed admission was traced
to a fixed-size TokenElevation query incorrectly using variable-length sizing.
No additional elevated/provider run followed the consumed one-attempt permission.

Isolated file-only Tamarin checking at `f6bf2c0` verified the retained stronger
approval witness in 43 steps / 6.87 seconds. Replacing its proof with `sorry` or
`contradiction` produced the required incomplete result. Denial proof checking at
`f905af3` also passed: 42 steps / 7.10 seconds, with both altered proof bodies
incomplete. These are checked stronger formulas, not a normal-gate pass; their
explicit implication/source mapping and normal-gate integration remain pending.

The later07b34fd checks completed: Windows fullRust13m41, Linux9m25,
Androidcore2m52, actualAPK/Kotlin7m56, Windowspackage11m12 and notificationrenderer
6m9 passed. Its normal protocol gate proved all six request-safety properties
with fresh same-invocation helpers and all pinned-channel checks. Three original
honest request witnesses and two request canaries timed out; the overall protocol
gate remains failed. Earlier individual runs below retain their own scope.

The isolated one-time Windows context diagnostic is retained on
`codex/pcp-context-probe` at7545210. Its corrected nativebootstrap passed build and
PE/payload checks, then the user explicitly authorized one additional immediate
attempt. That attempt ran22:03:56–22:04:43KST and returnedE500000D/ERROR_INVALID_DATA
in admission, before creating the diagnostic service or either protected folder.
ROOT confirmed those objects absent22:06. No provider measurement was obtained.
The exclusive one-attempt authorization is consumed. Further Windows elevation
requires a new user request; read-only/source diagnosis can continue.

Android native boot/foreground lifecycle CI is the next implementation slice.
It needs a genuine x86_64 product build (Tauri plus matching controllerJNI),
instrumentation and host-observed reboot/update state. Existing policy JVM tests
and the separate notification renderer provide different, narrower evidence.

- `7b9df1f` Windows/Linux full Rust quality and Android Rust-core jobs passed in
  [Quality34461333180](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34461333180).
  The overall run failed its normal Tamarin job. Actual APK and Windows package
  runs also passed; this does not establish remote approval or native startup.
- `ServiceSession` now composes the existing registry, decision engine, original
  PC key, clock and bounded authenticated peer ownership. Do not build a second
  coordinator. The real Windows request producer, low-privilege carrier boundary,
  first-pairing caller and target-bound OS application are still missing.
- Consumer wording/activation UI is implemented and ROOT reviewed the final
  Windows/Linux 47-case,73-image galleries plus eight Android shared-renderer
  cases. Original screenshots are published in
  [issue1](https://github.com/115dkk/Windows_UAC_Remote_Controller/issues/1#issuecomment-5616495027).
  Renderer/client evidence is not real boot, phone authentication or UAC evidence.
- Real user-approved native installation of `7b9df1f` failed at the first
  `NCryptOpenStorageProvider` call with `0x80090030`; SCM recorded `0xE6070030`.
  An ordinary medium-user provider-open/close succeeded on the same machine.
  A fresh native service restart reproduced the failure.
- The separate `645991e` startup-order experiment moved the provider operation
  after acknowledged SCM `SERVICE_RUNNING` with no accepted controls. Its real
  installation at21:02KST still failed at the same provider operation. These
  experimental binaries are currently installed, with previous real-copy backups;
  the branch is **not merged**. No TPM/key reset, key deletion, service SID/ACL
  relaxation, UAC/Secure Desktop or antivirus change was made.
- Daybreak Blue proposed a separate fixed-function SYSTEM provider diagnostic to
  distinguish restricted-token effects from LocalSystem context. ROOT requested
  explicit user permission, which the user granted. The later diagnostic attempt
  is recorded above. The error
  alone does not prove TPM failure or an access-denied cause.
- Isolated protocol `65664b8`
  [CI34475391432](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34475391432)
  proved four helpers plus the unchanged revocation property together in19.26s.
  Its eight other original obligations and both request canaries were unselected.
  Earlier one-property diagnostics proved five other request-safety properties,
  but witnesses and required canaries remain incomplete in the normal gate.
  Integration of same-invocation helper checks is under development, not a pass.

## Reuse these owners; do not build alternatives

| Responsibility | Existing implementation | Missing reachable integration |
| --- | --- | --- |
| Approval state and one-shot decisions | `approval-core::ApprovalEngine`; `approval-protocol::SignedDecision` | Actual Windows prompt capture/dispatch owner and target-bound OS application |
| Encrypted framing/carrier | `secure-channel`, `framed-transport::PeerTransport`/`SocketDriver`, `relay-service::connect_rendezvous` | Windows low-privilege carrier/service boundary and deployed cross-device provisioning |
| PC identity and registration | `windows-identity::PcIdentityKey`; `windows-service-host::ServiceRegistry` and `ServiceSession` | Resolve native provider initialization; protected real enrollment caller, carrier and prompt/OS integration |
| Phone hardware-key adjudication | `android-attestation::verify_key_bundle`, fixed-origin status fetch, required `VerifiedKeyBundle` registry input | Production ceremony and app-signer policy; never replace with a trusted boolean |
| Enrollment confirmation | `service-protocol::pairing`; `android-controller::pairing::PendingPairingAcceptance` | Original real QR ceremony, PC receipt producer and native callers |
| Android persistence | One `MobileController`/`DurableInbox`, Preparing/CreatedUnverified commits, ABI9 one-shot native creation transaction and existing pending acceptance | Real ceremony/scanner must call the existing owner; no second journal/preference owner |
| Android native keys | One Application-owned `AndroidNativePlatform.keyStore`, ABI9 `create_local_key_set`, `DeviceKeyStore.createKeySet`, exact reopening/reference registry and original-clock admission | Real authorized ceremony caller; native generation alone is not enrollment |
| Android service and presentation | `ApplicationPolicyActor`, boot/foreground service, native intake and notification coordinators | Genuine first pairing/provisioning plus physical device acceptance |
| React/Tauri UI | Existing shared client, IBM Plex Sans KR, settings/request/history screens | Native pairing activation; the current pairing-unavailable state is intentional |

The earlier prerelease pairing map's proposed acceptance codec/phone commit
slice is now implemented. Do not implement it again. Its remaining original
ceremony/scanner/caller gaps still apply. Likewise, attestation and installer
payload packaging are present; older documents describing them as absent are
historical.

## Actual checks before the consumer-copy change

- Quality run34451023513: Windows full Rust/Analyzer/canaries14m8, Linux8m59,
  Android Rust target3m29 all passed. The whole run is RED only in its separate
  Tamarin job; ROOT collected native watch exit1.
- Android package34451023504: actual APK and Kotlin tests passed7m25.
- Windows package34451023482: installer build/passive payload checks passed11m32.
- UI gallery34439778443 at the unchanged a40ee3b client: both44 cases/65 captures, with actual custom font
  observations; ROOT reviewed representative original PNGs.
- Android notification renderer34451023577 passed5m11. This isolated renderer
  test is not physical phone approval/authentication or full production proof.
- Tamarin's pinned-channel properties and two request-binding properties passed;
  seven request baselines and two request negative controls timed out. The
  normal gate remains failed. No counterexample is asserted for secure source
  merely because proof search timed out.

## Current implementation assignments

1. Android key creation: connect the existing durable Preparing intent to the
   existing Application-owned native creator, then exact CreatedUnverified
   persistence and the existing pending acceptance. Narrow callback ABI9; no
   public raw Tauri create/sign API or fake original ceremony.
2. PC TLS signing: owned private-constructible Server CertificateVerify witness
   and a bounded intra-trusted-process bridge to the original thread-affine PC
   key. This does not implement low-privilege IPC or authorize enrollment.

Both slices are implemented and passed the exact a8cf6c4 quality/package CI above.
Static review corrected acceptance-time stop handling, explicit cleanup-retry
ownership and native generation admission after waits before that validation.
Do not implement either slice again. ROOT alone executes validation. The next
integration must retain one original clock/owner, current registry revisions,
bounded work and explicit fail-closed state. Native key generation does not mean
enrolled; an authorized decision does not mean Windows applied it; SCM Running
does not mean remote requests are ready.

Those next slices, `ServiceSession` and G010 consumer wording/presentation, are
now implemented and validated at the scoped7b9df1f baseline above. They do not
create a production listener, QR ceremony or Windows prompt producer.

The isolated formal branch proved `building_precedes_open` and its dependent
`request_opened_unique` together in baseline and both fixed negative-control
contexts (e237a73, run34457423427; 4.37s/4.30s/4.32s). These are helper proofs,
not the original security properties or the required counterexamples. The normal
security gate remains RED; no experimental branch has been merged into it.

## Remaining release blockers and execution boundaries

Real QR issuance/scan and first enrollment, Windows live prompt/peer/decision
composition, target-bound Secure Desktop application, credential-type feasibility,
required formal proofs, final security audit, fresh approved architecture pass,
release automation and native acceptance remain unfinished. No usable full-product
prerelease has been published.

The22:00KST window ended. The subsequently authorized single attempt is also
consumed. The one-time reminder was deleted; further elevation requires new user
direction. Local screen access remains
unavailable; CI galleries and supplied images are the visual evidence paths.
C/E cleanup waits until actual prerelease publication, not just a
draft/build. Preserve source, keys, user data and sufficient release/evidence
artifacts. Low disk space is not permission to delete them early.

ROOT remains the only validation executor. Child work is source authoring or
static review, not proof. Preserve the last preauthorized reset credit until the
user's remaining-usage threshold is met; an available credit is not itself
permission to consume it early.
