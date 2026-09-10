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
`collection`, `cleanup`, `bootstrap_error`, `guard_stage`, `guard_scope`, `service_process_exit`, and bounded
key/value token/provider metadata in `probe`. It is not overwritten on failure.
The retained result directory is evidence and is not part of automatic cleanup.

Exit 0 means the provider attempt was recorded and diagnostic service cleanup
completed; inspect `pcp_open_status` and `pcp_free_status` independently.
Attributed early admission failures use `0xE5SSCCCC`: `SS` is the fixed guard
stage byte and `CCCC` is the original Windows-error low word. A bounded stdout
JSON receipt also retains the full error DWORD and fixed scope; no writable
directory is needed. Stage zero means an older/unattributed failure, not a
successful guard. Exit 1 means an unclassified exception. Exit 2 means
bootstrap work or cleanup was incomplete; inspect the protected paths before
any further action. Exit 3 means cleanup completed but the payload did not
complete its provider observation. `payload=complete` describes completion of
the attempt, not a successful HRESULT or production end-to-end behavior.

This diagnostic does not establish the cause of the production startup failure;
it supplies one separately attributed context observation. It must be reviewed
and compiled before the user's authorized native run.

## Separate unelevated, read-only guard test

The one authorized elevated attempt has been consumed. This addition authorizes
no second bootstrap, install, service start or provider attempt. ROOT reported
that the `7545210` bootstrap exited `0xE500000D` before creating the diagnostic
service or either directory. That code alone does not identify which guard
failed. No new native result is claimed by these source changes.

`PcpContextProbeGuards.cpp` includes the same bootstrap source with the compile-time
`PCP_CONTEXT_READ_ONLY_GUARDS` definition. It is a separate `asInvoker` executable,
not a new argument or mode in the elevated bootstrap. It accepts no arguments
and rejects `TokenElevation=true` before its path/ACL checks. ROOT may compile
and run this bounded read-only test under ordinary privilege only.

Example ROOT-only build from a reviewed x64 MSVC environment, in a separate
output directory (substitute only the source directory in the build command):

```text
cl /nologo /std:c++17 /EHsc /W4 /WX /MT /O2 /utf-8 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 /guard:cf /Fe:PcpContextProbeGuards.exe /Fo:PcpContextProbeGuards.obj <source-directory>\PcpContextProbeGuards.cpp /link /WX advapi32.lib /MACHINE:X64 /SUBSYSTEM:CONSOLE /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /GUARD:CF /DEPENDENTLOADFLAG:0x800 /MANIFEST:EMBED "/MANIFESTUAC:level='asInvoker' uiAccess='false'"
```

The actual linker command supplies `asInvoker/uiAccess=false` and System32 load
flags. MSVC rejected the earlier object-file pragmas with LNK4229; those pragmas
were removed. ROOT inspects the final manifest/imports before running.
Do not link `PcpContextProbe.res`, a managed payload, or the elevated bootstrap's
manifest. Invocation is only `PcpContextProbeGuards.exe` with no arguments; it
contains no elevation-launch API or retry.

Preprocessing excludes `adminOnly`, payload/resource loading, all SCM operations,
file/directory creation, protected result writing, and service/file/directory
deletion. The read-only build keeps only token/SID inspection, fixed directory
opens with `OPEN_EXISTING` and read rights, path/ACL inspection, stdout receipts,
and release of its own handles/local allocations. Neither existing installation
nor results paths are read, written or removed by this test.

The actual shared inspector queries the current process's user/session/elevation/
token-type layout and Administrators membership. SYSTEM, session zero and
non-primary token rejection remain shared. Elevation and administrator membership
are still both mandatory in the production `adminOnly` function; the test instead
requires unelevated execution and does not require active administrator membership.
It also exercises the actual SID-bound helper with a public well-known SID and
fixed truncated/revision/subauthority-count negative cases, checks the existing
case-insensitive System32 predicate, then runs the identical pinned `C:\` and
strict `C:\Program Files` path/ACL admission. No ACL mask, trusted SID, reparse,
canonical-path or hardlink predicate was relaxed.

Each stdout JSON line uses `guard_schema:1`, `read_only:true`, `accepted`, `scope`,
`stage`, and `win32_error`. Successful per-scope lines do not imply complete
bootstrap admission. Exit zero means only these read-only checks completed;
`0xE5SSCCCC` identifies a rejected guard, and exit one is an unclassified exception.
The exact stage mapping is the `GuardStage` enum in the shared source:

| Coordinate | Meaning |
| --- | --- |
| Scope 1 / 2 / 3 / 6 | Process token / volume root / Program Files / system directory |
| Stage 2 | Elevated execution rejected by the read-only entry |
| Stages 10–23 | Token open, layout/query, required property or exact four-byte scalar |
| Stages 32–36 | SID header, revision, count, allocation bounds or validity |
| Stages 48–58 | Security descriptor, owner or ACL admission |
| Stages 59–68 | ACE bounds/type/flags or access-mask admission; 67 is unknown mask, 68 is untrusted write rights |
| Stages 80–91 | Pinned path capacity, open/metadata, disk/reparse/type/link or canonical-name admission |
| Stages 100–106 | Bootstrap image/system directory/resource/process preflight; most are excluded from the test |
| Stage 110 | Fixed malformed-SID/bounds regression checks |

No path, SID bytes, user name, credential, key or token buffer is printed. A
read-only failure at the same common guard can narrow the earlier admission
failure, but the unelevated token is not the former elevated token. This test
does not reproduce elevated membership/access checks, the bootstrap's exact
image location, embedded payload validation, SCM access, process timing, directory
creation or LocalSystem/provider behavior. A passing read-only result therefore
cannot explain or clear every possible earlier admission failure. A new elevated
or provider run would still require separate user authorization.

Child authors performed source inspection and editing only: no compile, test,
hash, CI, service/provider execution, installation or cleanup. ROOT owns actual
read-only compilation, manifest/import review, execution and result attribution.

ROOT's ordinary-privilege run isolated information class20 (`TokenElevation`):
NULL/zero-length sizing returned FALSE, required4bytes, native error24
(`ERROR_BAD_LENGTH`). The generic122-only sizing guard rejected this response.
Fixed-size type/session/elevation fields now use one initialized four-byte query
and require exactly four returned bytes, in both C++ and the C# payload. Variable
SID/group blobs retain their bounded two-pass handling. This follows the fixed
DWORD shape of [TOKEN_ELEVATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_elevation).

After the change, ROOT compiled with compiler/linker warnings-as-errors and ran
the ordinary-privilege guard executable: token inspection, malformed-SID fixtures,
SystemDirectory, C: root and ProgramFiles guards passed, exit0. The elevated
bootstrap and provider operation still need a separately authorized future run;
the user's prior one-attempt authorization is consumed.
