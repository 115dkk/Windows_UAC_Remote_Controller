# Alpha39 work record (in progress)

Baseline2926af0301b0e7f7b37a22083ba716bbcaa0c939 = published alpha38.
Current branch codex/native-runtime. All product work below is uncommitted until
security fixes/review finish. Existing .codex-remote-attachments remains untouched.

## User scope

- Cold-boot PC service failure; preserve manually restarted service.
- Phone history must distinguish authenticated PC approval/denial/failure.
- Remove boxed relay boilerplate; PC overview uses real phone connectivity,
  removes PC-service eyebrow and reads 승인기 실행 중; remove unsupported local-UAC fallback.
- Suppress short connection-display flaps on PC and phone, not native deadlines.
- QR/USB equal emphasis, QR first.
- Phone can forget offline PC with confirmation, no PC/network required.
- PC logs request delivery failure when no connected eligible phone accepts queue.
- Notification approve/deny can retire phone owner: fix operation-local handling
  and consumed one-shot notification recovery without replaying old action.
- Commit/push, CI only validation, exact SHA review and published Windows/APK
  prerelease required. User asleep: no real auth prompt, UAC or reboot requested.

## Observations

Read-only Windows startup diagnostic:2026-09-20T02:16:42.3535558Z,
alpha38 PID5916 stage7 phase=scm class=configuration code00000000 policy0.
SCM7024 same time, boot11:16:34KST. Config read with sc qc/qsidtype succeeds and
matches AutoStart/OwnProcess/LocalSystem/no dependencies/Unrestricted SID.
Current PID24688 created11:19:08.8767KST remains Running after user manual start.
User screenshot shows PC approval11:14; phone showed generic PC completion.
ProgramData private directory read was denied; stopped that path, user supplied
PC history screenshot instead. Do not retry/elevate that read without authority.

The Started journal event is once per process startup, not heartbeat. Screenshot
11:19 agrees with actual process creation. WatcherAlive/WatcherStarted are omitted
by pc_history projection. Moved Started after actual Ready acknowledgement.

Physical phone USB debugging explicitly authorized later. Configured adb:
C:/Users/32170336/AppData/Local/Android/Sdk/platform-tools/adb.exe.
ROOT selected the user's physical SM_S948N, not emulator-5554; no serial retained here.
Only bounded UacBoot/UacNative logs and current app service observation read.
Phone PID22162 owner_phaseREADY, LOCAL_SETTINGS_READY. Surviving logs contain
ordinary admissions at11:32/11:43/11:45/11:49, no incident exception. No real
approval/auth/device mutation performed. Exact physical incident cause remains
unobserved; source defect and regression evidence will be reported separately.

## Current implementation

- Startup: split strict registration from running selfPID check. After existing
  Running/no-controls ack, query until observed Running/selfPID, waiting only
  StartPending or absent PID(None/0), no controls; nonzerowrongPID/config/state
  errors fail. Original30s deadline/stop guards before/after queries, before
  SetSecurityInfo and final completion. Strict later rechecks unchanged.
  Add SCM status/state/process/controls phases; PowerShell positive parser tests.
  Existing log does NOT isolate staleStartPending; timing remains hypothesis.
  Official reference:https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex
- History: authenticated RequestResolution Approved/Denied/Failed previously
  collapsed into Completed. Preserve distinct outcomes through lifecycle,
  outbox, journal and UI mapping; keep old tag4 unknown; new tags5/6/7.
  Signed native carrier test expanded across all3 outcomes (local choice always
  approve, returned PC result authoritative). Legacy history compatibility tested.
- PC connectivity display now uses devices, not hardcodedfalse remoteRequestsReady.
  Shared useConnectionDisplay keeps prior confirmed connected text for at most
  10seconds (two foreground polls) through rawfalse; unknown, ownerstop, identity
  change invalidate immediately. Raw snapshots/action gates never changed.
  PC peer connection display now also requires ready+clock_served, not rawactive.
- Both QR/USB controls secondary with existing spacing; no layout redesign.
- Offline removal: native forget_pc resolves current exactPC association under
  sole admission, durably revokes, closes matching peers and prunes revoked
  operations. Shared local keys retained. Origin-bound Tauri/Kotlin worker path
  REMOVE_PEER, readyphoneowner required, not PC connectivity. Confirmation UI.
  New bridge ABI13, synchronized Kotlin/tests. No approval API added.
- PC observed request queued to zero phones logs existing FailureKind::DeliveryFailed,
  mapped to distinct delivery_failed UI. Not emitted for idle/heartbeat/renewal.
- Notification: security_review owns Kotlin coordinator/DenialJob/pure policy
  fixes/tests. ROOT owns actor callback(Throwable) plumbing and new exact-native
  refresh_native_request method in effects.rs (same current-handle/fullbinding/
  policy check then Update/noalert, original binding/expiry retained). Agent
  integrates one bounded fresh ticket after definite noadmission, no action replay.

## Review / validation status

Security-startup receipt exists; later None/0waiting and Readyjournal move need
final supplemental audit. Security agent implementing notification slice; no
other child writes expected. Fresh mandatory architecture phase NOT yet started
for this task. General Codex usage observed21% used before work; check fresh at
phase boundary. No reset authorized.

Root ran cargo fmt --all and git diff --check only, no local builds/tests/lint.
Version mechanically bumped alpha38->alpha39 in5 metadata files. No tag created.
CI all gates and real-target visual artifacts still required; no current pass.
Frontend root:.superloopy/evidence/frontend/20260920T024031Z-boot-outcome-status.
User images are current-surface delta evidence, not reference style authority.
Skills read:make-interfaces-feel-better +surfaces, superloopy-frontend +ux/web/
desktop/mobile/hybrid/image-first/layout. Existing design tokens remain owner.
