# Development handoff — 2026-09-11

This inventory prevents duplicate implementation. It is not a readiness claim.
Last fully passing quality revision: `cbac9627a4889db6b74d1015ff9cf7a23d3ec1ec` on
`codex/native-runtime`. New Windows renderer-bootstrap changes are in progress
after that revision and require their own ROOT checks. No prerelease is published.

## Latest evidence — September 11 night (Claude root)

Everything here is backed by exact local gate runs or CI run ids; device and UAC behaviour remain
unverified.

- `15e6043`, `a8f5467`, `cfb2604`: the service watch session (W6b), relay configuration and registry
  device routes (W3 parts A and B), the phone-side enrollment ceremony, relay dialer and version 2
  associations (W4, ABI 11) and the Kotlin ceremony wiring (W7) landed after root validation (fmt,
  crate tests, Clippy with all features, the Rust Analyzer gate). Worker code needed real fixes before
  it passed: the scan-derived clock refused the native creation callback, synthetic certificates
  lacked a DER header, a fake PC queued frames before TLS readiness, a test mock kept the owner lease
  alive through a reference cycle.
- Lab runs 34601162152 and 34609160710: the hosted runner's Software KSP reports implementation flags
  34 (software plus virtual isolation) and answers `NTE_BAD_KEY_STATE` to property reads on an
  unfinalized key; with the restricted service SID `NCryptFinalizeKey` fails with `NTE_PERM`
  (`0x80090010`). Restarted with an unrestricted service SID the same binary created the key and
  stopped at the descriptor policy (`ProtectedServiceDaclRequired`). ADR 0028 therefore registers the
  service with `SERVICE_SID_TYPE_UNRESTRICTED` (`89c1a74`). Run 34610113157 then showed the Software
  KSP mapping each ACE mask to `0xD01F01FF`; the descriptor policy accepts that mapped full-control
  form for the two fixed principals (`130a325`). Release packaging refuses lab-profile binaries.
- Lab run 34611959940 (`a5c4fa3`): the service reached `Running` on a hosted runner for the first
  time (key created, trust journal and activity journal written, `probe-once` accepted). The probe
  supervisor then refused with `restricted_token_mismatch` (fixed in `2ebfa6c`, together with the
  helper's own token check), and the scheduled-task elevation request produced no `consent.exe`
  within 15 s; the next lab run records a 40 s process timeline and the task's status.
- Android signing: a repository keystore and the four `ANDROID_*` secrets now exist, so `release.yml`
  signs the APK with a stable key and embeds its digest into the Windows build.
- The lifecycle READ probe expected snapshot schema 3; the app has published schema 4 since the
  pairing view landed. Fixed in `cfb2604`; the scanner extension is still unproven.
- `4594449`: the PC side of the enrollment ceremony landed (W3b): invitation from the protected relay
  endpoint, enrollment stream over the relay with attestation verification and mutually pinned TLS,
  frozen candidate signed by the PC identity key, comparison on the renderer, registry commit and
  engine mirror, signed acceptance, and a dedicated dialer that keeps one relay connection per
  enrolled device after Ready. 234 host tests pass in the service crate; loopback fixtures needed
  Windows-specific socket handling (resets on early drop, nonblocking accepted sockets).
- Lab at `733cc57`: probe-once was refused by the supervisor's token facts (TokenHasRestrictions
  answered with fewer than four bytes; now read as a flag). No consent.exe appeared because the
  runner administrator has no filtered token and a SAFER basic-user token elevates silently; the
  lab now creates a standard user and requests elevation through Secondary Logon.
- Lab run 34618803758 (`8606928`): a standard user created on the disposable runner requested
  elevation through Secondary Logon and a real `consent.exe` appeared in the interactive session
  while the service was Running. The probe supervisor then stopped at
  `SetTokenInformation(TokenSessionId)` with `E_ACCESSDENIED` although SeTcbPrivilege was observed
  enabled (and explicitly enabling it changed nothing, run 34620877517). A SYSTEM scheduled task
  reproducing the exact call sequence (run 34622593419) showed the cause: a duplicate requested with
  the explicit `QUERY | DUPLICATE | ASSIGN_PRIMARY | ADJUST_SESSIONID` mask is refused, while
  `MAXIMUM_ALLOWED` and `TOKEN_ALL_ACCESS` duplicates accept the session change. The next run
  isolates the missing right so the supervisor can request the minimal mask.
- Scanner extension at `8606928` and `32d3baa`: the native gate opens, the client renders and
  clicks the button, and the Kotlin open path is never reached (`launch=null`, no plugin log, no
  visible notice). The cause is the Tauri capability: `src-tauri/capabilities/main.json` allowed
  nine of the eleven registered commands and never listed `open_pairing_scanner` or
  `request_details`, so Tauri 2 rejected both invokes at the IPC boundary. Fixed with the two
  permissions and a quality-gate test that keeps the handler, the capability and the permission
  files in step. Lifecycle run 34622848234 (`2049da8`) then passed every original phase, the first
  unlock and both scanner cases (secure native Dialog opened from the client button, cancelled on
  host stop, 68 no-QR view renders). At `2049da8` Quality, lifecycle, both packages and the gallery
  are all green.
- What remained at that point (W9, W10, green CI, the lab's session change) is recorded in the next
  section.

## Latest evidence — September 11 evening (Claude root)

Codex froze product work at `6da41e0`; Claude Fable 5.1 continues on `codex/native-runtime`.
This section records what is verified by exact runs; everything else below it is history.

- `ff3a111`: the stale ABI 9 assertion and the lifecycle WebView wait (one evaluateJavascript
  reply capped at 2 s inside a 30 s deadline) were corrected. Lifecycle run 34591263495 then
  completed every original phase and the first unlock; its new scanner extension failed at the
  native Dialog wait (no window within 30 s). Bounded failure diagnostics were added for the
  next run; the cause is not yet established.
- Hosted `windows-2025` runners (probe run 34591263436) have an interactive admin console
  session, `ConsentPromptBehaviorAdmin=0`, `PromptOnSecureDesktop=1` and NO TPM; opening the
  Platform Crypto Provider there returns `0x80090030`, the same code the installed service
  reports on the developer PC. ADR 0027 therefore adds a compile-time `lab-software-identity`
  feature (Software KSP) for a disposable CI lab; release packaging must reject it.
- ADR 0027 fixes the prerelease design: relay-rendezvous enrollment stream (plaintext
  `CandidateSubmission`, attestation verification, TLS upgrade, frozen candidate, phone and PC
  confirmations, signed acceptance), a protected QR/code display in the existing renderer child,
  a service-owned outbound relay dialer, protected relay configuration and a build-time Android
  signer digest. `service-protocol` gained the two new codecs (53 host tests, Clippy clean).
- A tag-driven release workflow (`release.yml`) builds the Windows installer, a signed arm64 APK
  (repository keystore or a documented ephemeral key), relay binaries and SHA256SUMS, and
  publishes a GitHub PRERELEASE with notes from `docs/RELEASE_NOTES_TEMPLATE.md`. Publication is
  packaging evidence only.
- In progress under root validation: renderer UI (W2), prompt watcher and exact-target Invoke in
  the helper (W6a), phone ceremony worker and dialer (W4, ABI 11), Windows shell pairing entry
  (W5), scanner Dialog states (W8, landed at `22c8459`; Android package CI passed). Still to
  start: service enrollment carrier and dialer (W3), watcher supervision (W6b), Kotlin wiring
  (W7), management query pipe (W9), prompt-to-phone-to-apply session integration (W10).
- Unchanged: no new personal-PC UAC/TPM experiment; the restricted-token hypothesis for
  `0x80090030` awaits the user's decision on the staged one-shot diagnostic.

## Latest evidence — September 11

Latest user steering replaces bespoke license investigations and collection with
Cargo Deny. `deny.toml` and a commit-pinned upstream Docker action now own the
Rust license CI check. ROOT executed official cargo-deny0.20.2 with locked,
offline, all-feature workspace inputs and received `licenses ok`. The original
material scripts/assets remain preserved but are removed from default quality
checks/collection. No further manual notice search is planned.

### Current verified baseline and remaining implementation

At `cbac962`, all five triggered workflows completed successfully:

- [Quality 34564518693](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34564518693):
  Windows/Linux full quality, actual Rust Analyzer and canaries, Android Rust
  core, Cargo Deny and the Tamarin protocol obligations.
- [Windows package 34564518754](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34564518754)
  and [Android package 34564518711](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34564518711),
  including the actual Gradle unit-test task.
- [Native Android lifecycle 34564518701](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34564518701)
  and [notification renderer 34564518735](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34564518735).

ROOT verified 577 native command logs and three metadata files in memory and
retained a bounded 15-file original subset. Seven phases and twelve observations
passed. One actual pre-input System UI snapshot expired after 5309.929709 ms;
the bounded repair discarded it without issuing input, captured a fresh layout,
and completed the sole synthetic unlock attempt. The original 5 s/120 s and
command limits remain. First unlock was observed; physical authentication and
request delivery were not tested. The earlier `93f9289` ordinary-launch owner
failure did not recur. Its cause remains unknown; `cbac962` adds bounded stage
and first-failure diagnostics, not a claimed lifecycle repair.

C4's policy watcher and one-use private ceremony preparation are included in
this passing baseline. The newer C5 slice adds the fixed, from-creation private
renderer, registered suspended-child launch and direct service-to-renderer
channel. It is currently **nonvisual and unvalidated**: no QR, window, graphics,
desktop switch, secret release or enrollment is enabled by that slice.

The product still needs an actual QR/scanner-to-enrollment path, provisioned
initial and paired connectivity, the live Windows prompt owner and exact-target
approval/denial application, release signer/provisioning integration, and physical
acceptance. Existing Windows capture is read-only; the signed-decision branch
still returns `AuthorizedButNotApplied` because no live OS application adapter
is connected. These are implementation gaps, not merely deferred user tests.
Credential-prompt support remains conditional on meeting Windows authentication
requirements; unsupported types must be ignored.

The installed Windows service's platform-provider failure (`0x80090030`) is
unresolved. The last authorized one-shot experiment was cancelled by the user
at 05:46:10 KST on September 11 and is consumed. No further local UAC/provider
experiment is authorized. Local Rust/Gradle builds remain stopped for disk space.

At 14:49 KST the general Codex bucket was 37% used / 63% remaining, with no reset
credits. The 50%-remaining Claude-handoff condition has not fired, and the genuine
final architecture phase has not begun. No bridge was launched and no C/E files
were deleted. Cleanup is due after actual prerelease publication, or as part of
that explicitly authorized conditional handoff.

### Historical checkpoints

The checkpoints below retain their earlier revision-specific scope. Their
pending work and license-collection statements are historical; the current Cargo
Deny policy and verified baseline above supersede them.

At af1c5b9, both Windows/Linux code-quality steps passed, including the new
Step3 Windows fixtures, Clippy, full tests and actual Analyzer/canaries. The
overall Quality34556026261 failed only its later block2 notice collection.
Windows34556026310, Android34556026311 and renderer34556026228 passed.
Native lifecycle34556026283 failed16m47 at the first pre-input SystemUI
freshness check. ROOT retained/hash-checked433 command logs and three metadata
files; six phases, durable OFF behavior and three locked/no-native-owner samples
completed, but no unlock input was dispatched and first unlock was not verified.
This is a new harness failure, not a passing whole lifecycle or an established
Android runtime regression. A bounded pre-input recapture repair is under work.

ROOT's expanded original-notice collector now passed30 local fixtures and one
real offline observation:536 packages,887 materials,4382761 original bytes.
The exact47-consumer/30-asset policy includes explicit external-document origins
and incomplete-terms/explanatory limitations. No package was filtered. Full
license compatibility, corresponding source and publication remain separate;
new CI is required for this source change. The local generated output is retained
at target/license-materials/rust and must not be overwritten or blindly deleted.

The next Windows source slice is frozen/reviewed with ADR0025: pre-Offer native
UAC-policy watching and one-use private ceremony preparation in the same Session.
Review corrected secret-buffer wiping and two actual retained-key checks around
the one claim. ROOT's read-only PC observation also removed an inapplicable
built-in-administrator setting requirement for ordinary accounts. Formatting
passed; no new local UAC/provider execution or QR/enrollment authority exists.

At12:20KST general usage was27% used/73% remaining, and free space was
C680935424/E55521280 bytes. Conditional50% handoff/cleanup is not yet triggered.
ROOT has a read-only exact-path cleanup inventory; no drive files were deleted.

The following6fce71e checkpoint is historical and retains its exact scope.

At6fce71e, both complete Windows/Linux code-quality steps passed, including
Rustfmt, Clippy, tests, real Analyzer and canaries. The overall Quality workflow
34549153227 remains RED because the later notice collector stopped at block2
on both hosts. Windows package34549153266, Android package34549153272,
notification renderer34549153303 and native lifecycle34549153196 passed. No
original6f native artifact has been downloaded/reparsed as a new review.

The next source slice now implements a service-owned pairing rendezvous after
the actual full SCM Ready acknowledgement: untimed idle listeners, one original
five-minute admission window, exact helper identity matching and both CloseAck
receipts before closing either pipe. The existing Session retains all native
owners through stop/cancellation/drain. Independent review found a fresh-stop
gap before SCM StopPending publication; the revised source checks the actual
stop latch around positive work and retains cleanup availability. ROOT formatting
passed; new compilation and behavior evidence are still required. This is an
informational rendezvous, not QR issuance, enrollment or remote-UAC authority.

Original upstream notice assets for UniFFI, NDK and UNIC are being integrated
with exact package/version/license/source tuples. Further missing materials
remain unresolved; a source notice inventory is not compatibility clearance.

Latest user steering: if general Codex remaining usage reaches50% before the
genuine final architecture pass starts, ROOT freezes implementation, preserves a
committed Claude handoff, creates/runs the repository's desktop bridge, CLEANs
confirmed reproducible C/E outputs and caches, then ends Codex work. This is an
explicit exception to the ordinary post-prerelease cleanup timing. Source/Git,
keys, user data, required evidence and active bridge/project dependencies remain.
At11:23KST, actual general usage was18% used/82% remaining; no threshold action
has occurred. The last reset was already redeemed and zero credits remain.

The following591b937 checkpoint is historical and retains its exact scope.

At591b937 the canonical `pair` CLI, original-client-owned helper launch and
six-frame live rendezvous/terminal consumer are implemented, with ADR0023 and
bounded-source static review. The actual service pending-slot/endpoint producer,
QR/scanner and enrollment are still absent. No positive local UAC run occurred.

Windows package, Android package/Kotlin tests, notification rendering and real
Android lifecycle passed at591b937. This is the third successive native emulator
full pass with durable ON/OFF activation, following a72b0d0 and c21a4bc. The latter
two original artifacts were separately hash-checked/reparsed by ROOT;591b937's
workflow success is not a newly downloaded original-artifact review.

591b937 Quality is RED: Windows Clippy rejected one nested-if style; Linux passed
its code/Analyzer gates but the new original-license collector stopped at missing
alloc-stdlib notice material. ROOT's equivalent let-chain correction and narrow
reviewed shared-notice repair are awaiting new CI. The collector's22 local
fixtures passed. It collects actual source bytes, not compatibility clearance or
full corresponding source. Further absent notice material—including non-target
dependencies in Cargo's full metadata inventory—still needs source/membership
review. No package is silently removed or treated as legally cleared.

The following a72b0d0 checkpoint is historical and retains its exact scope.

At a72b0d0, all six triggered workflows passed: complete Windows/Linux Rust
quality with actual Analyzer/canaries, Android Rust core, real Tamarin, both app
packages, notification renderer, Windows/Linux UI gallery and actual Android
product lifecycle. The narrowly awaited focus assertion preserves the same
heading/presence/focus check; production UI behavior is unchanged. Android's
directory durability operation now uses the public O_NOFOLLOW/fstat/S_ISDIR API.

[Actual lifecycle34538785548](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34538785548)
completed all seven native phases and twelve observations with the durable
activation repair. OFF survived immediate real reboot and package replacement;
manual reopening stayed stopped. Explicit restart committed ON. The next
file-encrypted reboot retained ON while locked, with a foreground notification
and no Rust/native owner. Ordinary System UI entry of the public synthetic test
PIN produced READY before target Activity/instrumentation on that same boot.
ROOT retained all582 original hash-checked command logs, reparsed seven native
receipts and six System UI hierarchies, and checked the first-unlock predicates.
Physical authentication and request delivery remain unverified. This is an
emulator lifecycle result, not a completed remote UAC product or release.

The repair resolves the observed OFF-to-ON resurrection in this actual full
sequence. The previous failures below remain historical evidence; their exact
OS persistence cause was not established. New native Windows client source being
authored after a72b0d0 is outside this CI proof.

The following5534d16 checkpoint is historical and retains its original scope.

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
were authored and statically reviewed at that checkpoint. Corrected native
behavior is now covered by the a72b0d0 result above.
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
frozen-candidate owner integration are separate source slices subsequently
covered by5534d16 and a72b0d0 quality checks.

The checkpoints below are historical; the a72b0d0 result above is the current
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

## Latest evidence — September 12 early morning (Claude root)

- `d6e6c9b`: the live consent prompt now reaches the phone and the phone's decision is
  applied to the exact target (W10b, Daybreak Blue, with the root's fixes after a static
  review by ASTRA). One live prompt per session, one engine request per `Appeared`, the
  signed `Opened` published only to connections whose clock exchange is complete and
  re-sent once to a connection that completes it during the prompt, a matching signed
  decision applied once through the `PromptApply` seam to the same target and observed
  content digest, `Gone`, expiry and replacement resolving the previous request, `Applied`
  outcomes mapped to Approved, Denied or Failed, and engine requests consumed or dropped
  by a decision settling the live prompt at once. `RequestContent` accepts an empty path;
  the program name leaves out a Text label that would exceed its bound.
- `026c5c8`: lab run 34624753134 isolated the missing token right: the helper launch
  duplicate needs `TOKEN_ADJUST_DEFAULT` with `TOKEN_ADJUST_SESSIONID`. The next lab run
  (34635739158) launched the helper into the interactive session and a real consent
  prompt stayed on screen for over twelve seconds, but the journal recorded no
  observation, and `probe-once` now answers Busy because the running service owns the
  watcher. `74c80a6` journals the watcher's lifecycle (`watcher_started`, `watcher_alive`,
  `watcher_restarted`, `watcher_unavailable`) so the lab can tell a dead helper from a
  helper that scans and does not qualify the window; the lab now fails unless the
  journal holds an observed request. Its first run (34638615635) then showed a different
  failure: with the management pipe (W9) on a real service for the first time, the service
  entered Running and stopped one second later with WorkerFailed, before the watcher
  started. The next revision makes management activation non-fatal (journal kind
  `management_unavailable`, reason in the lab notes) so the watcher runs regardless.
- `f43df5a`: the android-bindings intake tests read the durable history under their own
  admission (the bare lock raced the reactor on windows-2025, run 34624753189).
- `9d0bf7a`: the management pipe (W9, Daybreak Blue, isolated worktree). The service verifies
  the connecting process (pipe client PID and session, process creation time, image pinned
  to the installed controller or service, token facts, session epoch); an installed
  medium-integrity GUI may query, the elevated CLI image may remove a device or set the
  relay. The controller runtime and the device panel show paired phones with their
  connection state and take the relay address; `set_relay` is registered in the handler,
  build manifest, capability and permission together. The worker's code did not compile
  as delivered (module depth, re-exports, serde for the device id, a changed read bound);
  the root fixed and validated it.
- `74c80a6`: the Linux quality and Android core checks failed on f43df5a because the
  watch session's `PromptApply` impl referenced the Windows-only peer runtime; the Tamarin
  gate's reviewed-source hash for `approval-protocol` is rebound to the empty-path change.
- Known limitations carried into the alpha: the helper's `Apply` message carries no
  original deadline, so a slow UI Automation invoke can land after the 110 s TTL on the
  same exact target; the Android pairing ceremony loses its one-shot objects when
  admission is busy (retry restarts the ceremony); the scanner instrumentation failed
  once with the owner closed and the camera reported unavailable (run 34624753148) and
  passed on the next run; the developer PC has not been re-tested (user deferred).
