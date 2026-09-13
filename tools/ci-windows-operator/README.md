# CI Windows operator (do not ship)

GPL-2.0-or-later. This executable is only for a disposable GitHub-hosted Windows
VM with an intact OS. It is not referenced by the product or release packaging.
It must never run on the developer machine. Build only in CI with `build.ps1`.

## Preparation and trust boundary

The ROOT orchestrator creates `C:\ProgramData\UacRemoteCiE2e` with a protected
DACL permitting only SYSTEM and Builtin Administrators, owner SYSTEM or BA,
and places `uac-ci-windows-operator.exe` plus `control.json` there. No reparse
points are permitted in either fixed path. The installed product must be at
`C:\Program Files\휴대폰 승인\uac-service.exe`, with no nonprivileged writes.
The operator verifies its own location and SYSTEM identity, interactive session,
fresh metadata, installed service SHA-256, local elevated client PID, and one-use
run claim. The protected metadata is the CI administrator's attestation of hosted
CI context; it is not a defense against a hostile administrator/SYSTEM.

`control.json` has exactly these fields (string values except the two PIDs):

```json
{
  "marker": "uac-ci-e2e-do-not-ship",
  "runNonce": "32 lowercase hexadecimal characters",
  "githubRunId": "decimal GitHub run ID",
  "githubRunAttempt": "decimal run attempt",
  "createdUtc": "UTC ISO-8601 time less than 60 seconds old",
  "sessionId": 1,
  "clientPid": 1234,
  "serviceSha256": "64 lowercase hexadecimal characters",
  "githubActions": "true",
  "runnerEnvironment": "github-hosted"
}
```

Launch the fixed operator with no arguments as SYSTEM in `sessionId`, using the
ROOT-provisioned Microsoft-signed PsExec. Before writing control metadata, Node
spawns the fixed `C:\ProgramData\UacRemoteCiE2e\uac-ci-pipe-bridge.exe` as its
elevated CI administrator, with private redirected stdin/stdout (never inherit
the CI console). Set metadata `clientPid` to this bridge child's PID, not Node's
PID. Publish the metadata atomically after spawn, within 60 seconds. Install
both executables with the same protected SY/BA-only ownership/DACL rules.

The bridge connects to `\\.\pipe\UacRemoteCiE2e.<runNonce>` with explicit
`TokenImpersonationLevel.Impersonation`. It verifies the kernel-reported server
PID, fixed installed operator image, fresh process creation, expected interactive
session and SYSTEM primary token using only limited process query/TOKEN_QUERY.
It retains the validated process handle for the lifetime of the connection and
forwards exactly the five ordered protocol requests/responses below. It accepts
no arguments or arbitrary path/pipe name. Both stdin and stdout must be redirected.
The bridge checks the same fresh protected CI metadata and installed service hash,
and itself must be an elevated non-SYSTEM administrator at its fixed path.

Node must not mirror pipe or bridge stdio traffic to CI logs. All protocol line
endings are explicitly LF, including .NET writers. Responses are bounded to
12 MiB per line, requests to 4 KiB. Pipe ACL is SY/BA. Exactly one connection is accepted. The
300-second lifetime watchdog terminates blocked UIA and pipe operations too.

## Closed protocol (UTF-8 JSON lines)

Each command has only the listed keys, one line <=4 KiB, no carriage return.
Responses are JSON lines; maximum image payload is 8 MiB base64 (6 MiB PNG).

1. `{"command":"arm"}` -> `{"status":"ready"}`. Rejects any preexisting
   consent in the target session. After this response, ROOT launches the fixed
   pairing starter through an actual filtered-token process.
2. `{"command":"capture_qr"}` -> `{"status":"qr_pixels","pngBase64":"...","rendererPid":1234}`.
   Waits for exactly one fresh System32 `consent.exe` in the session; examines
   its actual Winlogon UIA tree; refuses credential/edit controls; invokes the
   actual Show more details/자세한 내용 표시 view action when collapsed. It then
   requires a dedicated `Program location:`/`프로그램 위치:` Text label and a
   distinct immediate sibling Text value under the same consent.exe provider
   parent, identified by nonempty RuntimeIds and matching provider ProcessId.
   Virtual WinUI Text nodes need not have HWNDs; any HWND supplied must belong to
   the same consent process. The value must be the exact installed absolute path,
   optionally quoted, with either no suffix or only ` pair <64 lowercase hex>`.
   Other verbs, aliases, extra arguments, hidden controls and conflicting pathlike
   UI labels fail. A basename or FileDescription string alone never binds a
   location. Unsupported combined-field UI shapes fail closed for inspection.
   Exactly one visible enabled Yes button (English/Korean) from the same native
   provider is required. Invokes that actual button
   at most once. Waits for the fresh installed-service renderer HWND on the
   active `UacRemote.Pairing.*` desktop. Captures actual screen-DC pixels as PNG.
   ROOT passes these bytes in memory to the phone fixture's pixel QR decoder.
   The nonsecret renderer PID is available for diagnostic correlation.
3. After the phone fixture reports comparison pending,
   `{"command":"read_comparison"}` ->
   `{"status":"comparison_pixels","code":"six digits"}`. Captures pixels
   around the fixed comparison region; segments six glyphs and matches GDI
   templates rendered from the product's embedded UAC Sans Bold font. Ambiguous
   classification fails. ROOT sends this actual observed code to the phone
   fixture for validation against its own signed transcript-derived code.
4. Only after the phone fixture queues its confirmation,
   `{"command":"compare_confirm","code":"six digits"}` ->
   `{"status":"confirmed"}`. Recaptures/re-recognizes fresh pixels, compares
   exactly, and sends BM_CLICK to the actual visible native child BUTTON 1001.
5. `{"command":"finish"}` -> `{"status":"done"}`, clean process exit.

There is no later UAC approval command, arbitrary window/path/coordinate input,
shell execution, key/signature API or internal pairing DTO. The independent
fixture's signed denial must handle the later real UAC request through the
product path. ROOT verifies that later PC prompt closes; this operator does not
declare end-to-end success.

## Data handling and known feasibility gates

All PNGs, bootstrap QR content, observed comparison digits, requests and responses
remain only in process memory and this restricted local pipe. Never save them as
artifacts, logs, command-line arguments or screenshots. Exception contents are
discarded in favor of fixed phase/gate identifiers. .NET managed strings are not guaranteed
to be immediately erased; VM disposal and no dump/artifact collection are required.
No desktop ACL, UAC policy, Secure Desktop or OS protection is modified.

Actual Windows execution remains a required CI gate: hosted-runner session
availability; UAC Yes accessibility via UIA; target-label presentation; System32
consent process inspection; private-desktop screen capture; and digit template
matching at the actual DPI/font rasterization. Unsupported or ambiguous UI,
credential prompts, desktop transitions, capture/OCR failure and blocked calls
fail the job rather than substitute internal data or app approval flags.

FFI handle ownership: each fresh UI thread attaches before creating UIA/GDI
objects; input desktop handles close only after a successful detach. A UIA
hidden window preventing detach leaves that bounded handle until process exit.
Screen DCs, graphics HDCs, bitmaps, font resources and pipe handles have balanced
cleanup. There is deliberately no SwitchDesktop call and no DACL manipulation.
