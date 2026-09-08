# Windows service host

This crate owns the single `UacRemoteController` SCM service (display name
`휴대폰 승인`). `Running` describes its lifecycle worker only. It does not prove
phone connectivity, Windows prompt detection/approval, pairing, credential entry,
or encrypted transport. The serialized capability flags remain `false`.

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

`uac-service` with no arguments runs `status`. Accepted explicit commands are
`status`, `service`, `install`, `start`, `stop`, `restart`, `uninstall` and `help`.
Other/extra arguments are discarded without echoing them. There are no caller-
supplied service names, accounts, executables, paths, credentials or arguments.
Non-Windows operations return `UnsupportedPlatform`; native 64-bit Windows is
the supported installation target.

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
periodically and handles stop. Future transport and native prompt workers belong
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
