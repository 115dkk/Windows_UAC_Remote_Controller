# One-time PCP context diagnostic

This separate lab executable measures one `NCryptOpenStorageProvider` attempt for
Microsoft Platform Crypto Provider under a LocalSystem own-process service with
an unrestricted service SID, after actual SCM `RUNNING` and zero accepted
controls. It records public token metadata and raw provider/free statuses.
It does not use the production `UacRemoteController` service or its files.

## Build and authority

The isolated `codex/pcp-context-probe` workflow compiles the C# service with the
installed .NET Framework 4.x x64 compiler and `/unsafe- /warnaserror+`. Native
MSVC `/MT` bootstrap embeds that PE as resource 101. `/DEPENDENTLOADFLAG:0x800`
restricts initial dependent DLL loading to System32; subsequent dynamic loading
is restricted to System32. CI retains PE headers/imports/load configuration,
the elevation manifest, and source/binary SHA-256 provenance. CI only builds and
reads PE metadata; it does not install, start services, or open the provider.

ROOT must review the exact artifact/provenance and obtain the separately
authorized interactive UAC approval. The fixed launcher entry is:

`C:\Users\32170336\AppData\Local\Temp\uac-pcp-context-20260910\PcpContextProbe.exe install-run-remove`

This native bootstrap has no managed `.config` loading or staged payload reread.
Its executable image must itself be the ROOT-reviewed artifact at entry.
Parent source/path pins are defense in depth, not payload authority: the
elevated code copies its own already-mapped resource and compares the protected
copy byte-for-byte with that resource. No separate payload, hash, config, path,
service name, or operation argument is accepted from the caller.

## Fixed lifecycle

- Reject preexisting diagnostic service, installation directory, or result
  directory. There is no overwrite, repair, second start, or automatic retry.
- Create fresh protected directories with SYSTEM/Administrators full control
  and Users read/traverse. Pin canonical local paths and reject reparses and
  file hardlinks. ProgramFiles ancestors must pass the reviewed
  path/ACL admission checks.
- Install only `UacPcpContextProbe20260910`, demand-start, LocalSystem,
  own-process, unrestricted service SID. Its DACL protects start/configuration.
- The managed payload is fixed at
  `C:\Program Files\UacPcpContextProbe20260910\PcpContextProbe.Service.exe`.
  Its entry requires SYSTEM/session 0 and the fixed service dispatch argument.
- `OnStart` only starts the foreground worker. The bootstrap retains an actual
  process handle after checking SCM PID, image, and creation time, then creates
  the protected empty `observer.ready` marker. The worker observes actual
  `RUNNING`, matching PID, zero controls, and that marker before its sole
  provider call. The marker carries no operation data.
- The payload writes bounded public metadata to protected `probe.txt` with
  create-new semantics, then self-stops. No external stop/kill action is used.
- The bootstrap waits for both SCM `STOPPED` and the retained process handle to
  signal. Only then does it read the metadata, delete its service, observe
  service absence, and delete the exact fresh intermediate/marker/payload files
  and empty installation directory. No recursive deletion is used.

The bootstrap has one 60-second observation budget; the payload has a bounded
pre-provider wait. A native provider call already entered is not preempted. A
timeout or uncertain stop leaves the protected installation/service for explicit
review and reports incomplete cleanup. No key enumeration/create/open/delete,
signing, TPM reset, token alteration, network listener, or general process runner
is present.

## Retained result

`C:\Program Files\UacPcpContextProbe20260910Results\result.json` is a fresh protected
record retained for ROOT after the elevated bootstrap exits. It contains
`collection`, `cleanup`, `bootstrap_error`, `service_process_exit`, and bounded
key/value token/provider metadata in `probe`. It is not overwritten on failure.
The retained result directory is evidence and is not part of automatic cleanup.

Exit 0 means the provider attempt was recorded and diagnostic service cleanup
completed; inspect `pcp_open_status` and `pcp_free_status` independently.
Exit 1 means bootstrap admission failed (a result may not exist). Exit 2 means
bootstrap work or cleanup was incomplete; inspect the protected paths before
any further action. Exit 3 means cleanup completed but the payload did not
complete its provider observation. `payload=complete` describes completion of
the attempt, not a successful HRESULT or production end-to-end behavior.

This diagnostic does not establish the cause of the production startup failure;
it supplies one separately attributed context observation. It must be reviewed
and compiled before the user's authorized native run.
