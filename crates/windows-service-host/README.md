# Windows service host

This crate owns the single `UacRemoteController` SCM service (display name
`휴대폰 승인`). `Running` describes its lifecycle worker only. It does not prove
phone connectivity, Windows prompt detection/approval, pairing, credential entry,
or encrypted transport. The serialized capability flags remain `false`.

The SCM worker now restores a PC-key-bound device registry before Ready. Its
fixed private NTFS append journal preserves all three device key roles and core
revision highwater. Newly created PC identity permits empty initialization only;
an existing key with missing/corrupt state does not. No enrollment/QR caller or
live engine/peer update path is activated. See [ADR0007](../../docs/adr/0007-service-device-registry.md)
for transaction, maintenance and native-proof limitations.

## Public interface

- `query_status() -> Result<ServiceSnapshot, ServiceError>` is read-only.
- `install/start/stop/restart/uninstall() -> Result<ServiceSnapshot, ServiceError>`
  require a genuinely elevated Windows token and no thread impersonation,
  independently of UI claims. The check does not revert an impersonating thread.
- `request_elevated_control_from_ui(ServiceControlIntent) -> Result<ControlOutcome,
  ServiceError>` asks Windows to elevate only the fixed installed helper with one
  constant command argument. Invoke it only after explicit UI user intent and on
  a background task. User cancellation, a still-running helper, failed exit and
  completion whose status cannot be read are distinct outcomes. A helper launch
  alone is never a successful service operation.
- `dispatch_service() -> Result<(), ServiceError>` belongs on the service binary's
  main thread. The caller must exit on error, as the supplied binary does. There
  is no interactive daemon fallback or elevated relaunch loop.
- `request_probe_once() -> Result<ProbeRequestAccepted, ServiceError>` is the
  fixed elevated-only installed CLI diagnostic. It is not a Tauri/phone intent.
  Its successful JSON reply is `{"status":"requested","service_pid":...}`:
  accepted by SCM's one-slot handler, not probe completion or Windows approval.

`uac-service` with no arguments runs `status`. Accepted explicit commands are
`status`, `service`, `install`, `start`, `stop`, `restart`, `uninstall`,
`probe-once` and `help`.
Other/extra arguments are discarded without echoing them. There are no caller-
supplied service names, accounts, executables, paths, credentials or arguments.
Non-Windows operations return `UnsupportedPlatform`; native 64-bit Windows is
the supported installation target.

### Startup diagnostic metadata

SCM service-specific exit codes are distinct from the CLI's small process-exit
classes. Identity policy, malformed-data, encoding, uncertain creation/cleanup
and pre-identity startup failures retain explicit E1–E5 categories. No raw key,
path, command body or native error message is included.

An `IdentityWindows` error with HRESULT prefix `0x8009xxxx` is projected as
`0xE6OOCCCC`: `OO` is the stable explicit operation code in `contract.rs`, and
`0x80090000 | CCCC` reconstructs that HRESULT. This prefix includes NTE, SSPI and
CRYPT errors; it is not an NTE-only selector. For example, `0xE6070030`
means OpenProvider returned `0x80090030`; `0xE60C0030` means ReadKeyPolicy returned
the same error. These are application diagnostics, not HRESULTs or a diagnosis
of hardware failure. The original typed error still retains both fields.

HRESULTs outside that prefix pass through unchanged. Consequently this DWORD projection is
not an injective encoding of arbitrary HRESULTs plus operations: an arbitrary
outside-prefix value could collide with an application namespace. It is diagnostic
metadata only, never input to authorization, retry, cleanup or recovery policy.
The deployed lab service predates this operation-preserving projection; a future
authorized native run is required to identify its observed failing operation.

## Protected installation and registration

The native Program Files known folder, not an environment variable, determines
`휴대폰 승인\uac-service.exe`. Install verifies that the current
executable is exactly this protected binary, including its file identity. It
never copies a workspace/download binary into a privileged location.

The path proof opens/pins the local fixed-drive root, every existing ancestor,
the product directory and executable with actual data-read/list access and no
share-delete permission. Metadata-only access would not establish the required
sharing protection. Files share read only; directories also share write so that
fixed children can be created without allowing the pinned directory to be renamed.
It rejects
UNC paths, reparse points, aliases, hard-linked binaries and noncanonical paths.
Owners must be SYSTEM, Administrators or TrustedInstaller. Standard allow/deny
DACL ACEs are inspected conservatively; unsupported forms and permissive owners
fail closed. Unknown principals may not have replacement/owner/DACL rights.
Create-child rights alone on an existing ancestor, such as normal drive-root
permissions, do not count as replacement rights. Product directories/binaries
also prohibit unknown writers. Existing file handles do not justify bypassing
the ACL checks.

An existing SCM registration must match the exact quoted fixed executable plus
`service`, Korean display name, own-process LocalSystem identity, supported start
type, normal error control and empty dependencies/load-order group. Collisions
are never overwritten or removed. The service object owner/DACL and Restricted
service SID are checked before existing-service mutations. Ordinary authenticated
users receive only query-config/query-status service access, not start, stop,
custom controls, deletion or security changes.

Installation creates a disabled registration, restricts its SID, sets its service
DACL, provisions private activity storage, then switches to automatic start. It
does not start implicitly. A provisioning/hardening failure explicitly reports a
disabled partial registration; it does not broadly delete files or conceal the
failure. A stopped, verified own registration may be repaired by explicit
`install`. Start, stop, restart and deletion waits use one 30-second deadline
(restart shares the deadline across stop and start). Uninstall removes only the
registration and waits for Windows to report genuine nonexistence. It preserves
all installation and activity files.

## Private activity directory

Only explicit elevated install provisions the fixed native ProgramData paths
`휴대폰 승인` and `휴대폰 승인\activity`. Each new directory
is created atomically with Administrators ownership and a protected inheritable
DACL granting SYSTEM, Administrators and `NT SERVICE\UacRemoteController` full
control. This is needed for the service's Restricted SID write check. Existing
directories are validated, never taken over or cleared. An attacker-precreated,
user-owned, permissive or reparse-point directory causes installation failure.

At runtime the private parents remain pinned while `activity-journal` owns its
exclusive lock and performs bounded retention/atomic replacement. Existing
fixed journal files are checked for private ownership/DACL, regular-file shape
and absence of hard links before opening. Missing or damaged storage does not
lead to permissive creation, silent recovery or fake readiness. Journal events
are fixed typed diagnostics only; no raw paths, OS errors, keys, credentials or
command-line text is stored. Activity data is not authorization state.

### Narrow anchored ProgramData ancestor

The special private `pin_program_data_root` helper supports the observed
ProgramData Users mask `0x116` without changing the Windows DACL or weakening
ordinary ancestor/installation/private-data checks. All ancestors above the native
ProgramData root remain strict. The helper opens a provisional root handle,
verifies **NTFS and volume serial on that exact handle**, then pins the existing
fixed `ProgramData\Microsoft` directory with data/list-read access, no delete
sharing, OPEN_REPARSE_POINT and normalized expected-path validation. It never
creates, repairs or reads the anchor's contents.

Before returning any usable parent pins or performing a privileged descendant
write, it rechecks the original ProgramData handle's non-reparse/path/security
facts and NTFS identity. Holding the child entry keeps ProgramData nonempty;
the documented NTFS reparse operation refuses nonempty directories.
[Reparse restrictions](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points),
[FSCTL_SET_REPARSE_POINT](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point).
The root's own no-delete pin and strict higher ancestors protect its name.

Only this helper uses `AnchoredAncestor`: untrusted EA/attribute writes and child
creation are permitted, but untrusted owners, delete/delete-child, WRITE_DAC,
WRITE_OWNER, generic ALL/WRITE and unsupported access/ACE flags remain rejected.
The anchor may have metadata rights because only its retained entry presence is
used. Missing, inaccessible, linked, unsupported-volume or ambiguous anchors fail
closed; there is no alternate anchor or filesystem fallback. All four activity/
trust provision/open paths retain the complete ancestor/root/anchor pin set through
their existing IO lifetimes. Product, activity, trust, binary and data-file policies
are unchanged.

This fix is source-authored/unverified by its worker. Three new pure ACL tests
separate the exception from strict policies and reject replacement/security/unknown
rights; ROOT owns actual install, filesystem-sharing and reparse-race validation.

## Runtime/FFI ownership

Safe orchestration is in `native.rs`, pure policy in `policy.rs`, and the worker
seam in `runtime.rs`. Necessary unsafe code is private to `ffi/` and `entry.rs`;
the crate denies unsafe by default and ordinary source modules forbid it.
Owned OS allocation/file/token handles are released exactly once. SCM status
handles remain SCM-owned and are never passed to `CloseHandle`.

The control callback has no raw application context. A process-lifetime bounded
notification channel and atomic stop latch survive repeated Stop/Shutdown/
Interrogate calls without freeing callback state. Both Windows callback entries
contain Rust unwinds. The entry thread reports actual
START_PENDING progress, RUNNING only after worker initialization, STOP_PENDING,
and STOPPED only after confirmed worker exit. Pending phases are bounded. On a
timeout or reporting failure it returns a nonzero process result; worker-finished
progress does not restart an existing pending deadline. It does not
claim a live/stuck worker stopped successfully. The binary then exits, allowing
SCM to observe actual process termination.

The worker currently validates its installation, opens typed activity storage,
then opens the fixed TPM identity through `windows-identity`. Only `KeyNotFound`
permits creation; every other error fails startup. It validates public export
before Ready and explicitly closes the key on normal shutdown. No service or key
operation has yet been exercised by this implementation/review evidence.
Cancellation is checked between startup stages, including before key initialization;
an in-flight native CNG call is not made interruptible by these checks.

The worker records missing platform/transport integration, purges retention
periodically and handles stop. An explicit read-only diagnostic control can now
run the retained probe supervisor; it does not activate a prompt/action owner.
Future transport and native prompt workers belong
at the trusted Rust initialization/cancellation seam in `runtime::run`, not in
Tauri. The identity adapter's descriptor grants the service SID explicit rights
for the Restricted-token access check; actual provider behavior is an OS gate.

## Verification boundary

Unit tests cover argument, serialization, readiness, path, ACL, and deadline
contracts. No test installs, starts, stops or deletes a native service or opens
UAC. Only root runs validation. Passing pure tests is not Windows/Android end-to-
end evidence. Native installation, cancellation, startup/shutdown, ACL rejection,
partial repair and timeout scenarios need isolated Windows QA with explicit
permission. No Secure Desktop, UAC, LSA, firewall or other protection is disabled.
This includes launching the helper/SCM image while read-only file pins remain
open, installer write-handle closure before helper launch, key-provider
initialization under the Restricted SID, and ordinary Program Files/ProgramData
ACL layouts. Do not add write/delete sharing merely to make packaging pass.
The installer must separately establish package/dependency provenance; a fixed
path and ACL are not code-signature or loaded-module attestation.
The threat model assumes intact Windows/SYSTEM/kernel and trusted elevated
administration, while explicitly defending against unelevated local malware.

## Explicit read-only probe supervisor

`ServiceProbeSupervisor::for_running_service()` is an OS/SCM-guarded, thread-affine
owner. `probe_once(&mut self)` accepts **no path, session, command or target**.
The installed `probe-once` CLI validates actual elevation, its own protected file
identity, the service configuration/DACL/Restricted SID and a Running PID before
sending fixed user-defined control128. It confirms the same Running PID after
SCM accepts the control. The existing service DACL grants full control only to
SYSTEM/Administrators; ordinary users have query rights, not user-defined control.
The worker also checks that registration security before enabling the facility.

The SCM callback only latches one atomic pending request. Entry enables admission
only AFTER successfully reporting SERVICE_RUNNING; neither startup nor a
START_PENDING-to-Running race triggers a probe. The existing worker takes the
request and owns at most one supervisor for its lifetime. Pending/running requests
return Busy; initialization failure or unresolved quarantine disables further
diagnostics. No supervisor is recreated to clear quarantine. Stop atomically closes
admission, wins over later completion, and remains on the existing lifecycle path.
An in-flight synchronous native call is not made interruptible by this mechanism.

No renderer/Tauri/phone API exposes this operation. No helper is installed,
launched or exercised by this source-authoring evidence. Actual requests still
require ROOT's verification and the user's current native-experiment authority.

The supported subset requires an actual native64 Session0 LocalSystem/system-IL
process matching the fixed running OWN_PROCESS SCM registration and its protected
service executable. The SCM service must have Restricted SID configuration;
its SID must be enabled in the actual token and present in its restricting SIDs.
Impersonation query failures are failures; only ERROR_NO_TOKEN proves absence.
Every run rechecks token, configuration, session and retained installation pins.

The actual token must ALREADY have SeTcbPrivilege, SeIncreaseQuotaPrivilege and
SeAssignPrimaryTokenPrivilege enabled. If SCM supplies an explicit required-
privilege list it must include them; a null list is accepted, while actual token
checks remain mandatory. This is a deliberately conservative supported subset, **not**
a claim that Windows universally needs all three for every launch. No privilege
activation, required-privilege policy write, SID removal, desktop-DACL edit or
foreign-token duplication is performed. Missing rights return fixed errors.

Exactly one nonzero WTSActive session is selected natively. Its WTSSessionInfoEx
session/logon/connect observations are retained and rechecked; ambiguity, reuse,
missing information or an observed change fails. The service duplicates only its
own primary token, compares groups/restricted SIDs/privilege flags, changes only
the duplicate's session and checks again. The child token is queried and compared
to the same facts. No token is copied from another process.

Only the pinned protected sibling `uac-prompt-probe.exe` may be created. It has
no arguments, inherited handles or inherited user environment. Its working
directory is the protected installation and desktop is fixed to
`winsta0\winlogon`; access failure is not repaired by changing desktop security.
Creation is suspended. A fresh unnamed job has KILL_ON_JOB_CLOSE and an active
process limit of1, with no breakaway option. Both process and job committed-memory
limits are 256MiB, set before assignment/resume. This is not a working-set or
system UIA-provider limit; failed allocation does not prove child exit. The
empty job's Session0 creator is not falsely treated as a ban on its first
assignment to a target-session child; the actual assignment API decides.

Reporting uses one first-instance, remote-client-rejecting message pipe with a
new SYSTEM/service-SID-only DACL. No cross-session stdio inheritance is used.
The service matches the connected client PID/session to its retained created
child process, creation time, protected image path and token. The helper matches
the pipe's server PID/session to a retained actual running fixed SCM process,
SYSTEM/system-IL/service-SID token and fixed protected sibling path. Pipe names
and random challenges alone never authenticate either side. The leaf probe
crate owns the strict v2 40-byte challenge, 80-byte report header and bounded
content codec; one complete report is at most 512KiB. No
dependency cycle or generic RPC surface exists.

One fresh CSPRNG32-byte challenge is sent only after peer checks. The report
contains bounded visible static labels, a caption, comparison-only RuntimeId and
diagnostic counts on success; failures contain only fixed categories/numbers.
The probe excludes edit/value/password subtrees and makes no program/path/command
interpretation. Two matching capture projections do not establish atomic prompt
identity. Content is never included in Debug/error logging. Excess bytes,
duplicate/trailing messages, wrong challenge/version, malformed or oversized
content/counts/tags, EOF without report and inconsistent exit codes are rejected.
The owner returns no report until authenticated report + EOF + actual process
exit + empty job + fresh context checks. Helper exit3 (cleanup uncertainty)
cannot be accepted even if earlier report bytes arrived.

The service reads one message into a 512KiB+1 heap buffer, never a similarly sized
stack temporary. Connect, challenge and EOF operations allocate only their own
length. OVERLAPPED, buffer and event ownership remain stable until completion or
acknowledged cancellation; uncertain cleanup retains all of them. The 64KiB pipe
buffer setting is advisory, not a kernel memory cap. A successful zero-byte read
is not EOF and does not satisfy the required pipe-close observation.

The execution deadline is5seconds, with bounded overlapped waits; failure asks
only the owned child/job to terminate, then allows a separate1second cleanup
confirmation budget. This does not promise a universal wall-time bound on a
synchronous Windows call or OS scheduling. In particular, CreateProcessAsUser,
SCM/WTS queries and termination APIs may block. A failed termination or pending
I/O cancellation is never represented as completed. `is_quarantined()` remains
true, `quarantined_cause()` retains the original fixed error, and
`retry_cleanup()` only retries ownership cleanup (never launches). On an
unconfirmed owner drop the job is closed as another kill request, all remaining
kernel-referenced memory/owners and the process-wide lease are retained until
process teardown. A CloseHandle failure latches this process against reuse.
This intentionally trades bounded resource retention for no use-after-free or
overlapping helper launch. Job/process close is not a fabricated exit proof.

Pure tests cover no-input API shape, the shared fixed service identity, exact
deadline boundaries, unambiguous synthetic session selection and strict report
framing. They never call the Windows supervisor/helper/probe. Native launch,
actual privileges/desktop access, job restrictions, pipe authentication,
cancellation and cleanup still require ROOT's review and separately authorized
Windows QA. Content/counts remain observations; no Windows request identity, remote
approval, credential input or authorization action is implemented.

### Fixed body-free diagnostic slots

Source status for this integration is `implemented_unverified`; ROOT alone runs
all builds/tests/native checks. Eight authored pure tests cover CLI/no-UI routing,
one outstanding request, SCM-ready admission, Stop winning over queued/running
work, full/unavailable/quarantined states, byte bounds and content redaction.
They construct only synthetic report data and never call a Windows probe.

The existing pinned private activity-directory owner creates at most these files:

```text
<native ProgramData>\휴대폰 승인\activity\probe-once-01.json
...
<native ProgramData>\휴대폰 승인\activity\probe-once-08.json
```

The exact public constants are `PROBE_DIAGNOSTIC_FILES` and
`MAX_PROBE_DIAGNOSTIC_BYTES` (4096). Native creation uses only these fixed leaves,
CREATE_NEW, an explicit private descriptor, share0, OPEN_REPARSE_POINT and a
synchronous write-through handle. Existing slots are never overwritten, truncated,
removed, renamed or followed through aliases. Private ACL/owner, local regular
file, normalized path, no reparse point, one hard link and bounded size are checked
on the owned handle. The writer borrows the activity-directory owner so parent
pins remain live. Partial/failed files still occupy a slot. Full storage rejects
further controls explicitly; storage errors disable diagnostics. No automatic
operator cleanup/recovery or unbounded filename generation exists.

Each schema1 record contains only service PID, immutable correlation slot1..8,
optional actual start/finish Unix milliseconds, a fixed outcome, ProbeCounts,
cleanup classification and helper-exit classification. No caption, label text,
RuntimeId values, content hashes, paths, endpoints, keys, challenges or credentials
are passed into the serializable record. Success reports are projected to counts
and immediately dropped. Enum names/numeric native errors are stable metadata.

`report_and_exit_confirmed` appears only after the supervisor returns a fully
validated report/EOF/child-exit/empty-job result. On failure, `quarantined`,
`no_retained_run` or `unknown` describe only what the native owner actually knows;
helper exit remains `unknown` unless a verified report establishes it or no helper
was started. File flush is an OS acknowledgment, not a hardware/directory power-loss
guarantee. A missing, empty, truncated or invalid result is **failure/unknown**, not
evidence that no UAC prompt existed. CLI acceptance never promises a result file.

### ROOT build/install/trigger/read procedure

1. Run ROOT's formatting, Clippy and pure tests, then build matching native64 files:

   ```text
   cargo fmt --all -- --check
   cargo clippy --locked -p windows-service-host --all-targets -- -D warnings
   cargo test --locked -p windows-service-host
   cargo build --locked --release --target x86_64-pc-windows-msvc -p windows-service-host -p windows-prompt-probe --bins
   ```

2. In the separately authorized elevated installer, verify the exact built-file
   hashes and provision/copy only `uac-service.exe` and `uac-prompt-probe.exe` to
   `<native ProgramFiles>\휴대폰 승인`. Do not launch a workspace copy as an
   installation proxy, relax ACL/share checks, add privilege activation, or change
   Secure Desktop/UAC. Close installer write handles before invoking the files.
   From a native64 elevated shell, the fixed commands are:

   ```powershell
   $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
   $installedService = Join-Path $programFiles '휴대폰 승인\uac-service.exe'
   & $installedService install
   # Check the actual exit before continuing; install does not start the service.
   & $installedService start
   & $installedService status
   ```

3. Require actual successful exits and Running status. Existing TPM identity and
   registry initialization is unchanged and must succeed; a failure there is not
   a conclusion about Secure Desktop/UIA. Keep an already elevated operator context
   available so triggering does not add another UAC consent prompt to the sample.
   While the user holds the intended synthetic prompt open, issue exactly:

   ```powershell
   & $installedService probe-once
   ```

   Record its actual exit/accepted PID. There is one request, not a retry or scan
   loop. Stop initiating native experiments when the current user-approved time
   window ends. Use the existing fixed `stop` command for orderly service shutdown.

4. The elevated operator reads/copies only the eight fixed private slot files,
   checks regular/nonlink shape, <=4096-byte size and schema1 JSON, and correlates
   the new slot/PID/time with the accepted request. Preserve original evidence;
   never treat old files as a new result. No privileged service writes to a
   caller-selected export path. Required native gates still include actual process/
   privilege/restricted-token/session/desktop checks, protected-file sharing,
   authenticated pipe, UIA provider behavior and cleanup/exit confirmation.

Primary API basis: [CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw),
[token access rights](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects),
[job assignment](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject),
[CancelIoEx](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex),
[QueryServiceStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex),
[QueryServiceConfig2W](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2w).
See also the exact [job committed-memory limit semantics](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information)
and [pipe buffer advisory behavior](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew).
