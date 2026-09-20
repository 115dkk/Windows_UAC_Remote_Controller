# Windows desktop observer

Status: **root-validated read-only scope**, 2026-09-08. See
[root validation](../../docs/PROGRESS.md). This is a developer diagnostic boundary, not
product UI, authenticated UAC detection, phone approval, credentials or execution.
The implementation child did not execute validation. Root ran the tests, formatter,
Clippy, Rust Analyzer, Android cross-target check and the one-shot Windows query.
No actual UAC/Secure Desktop approval behavior has been validated.

## Read-only behavior

`observe_current_input_desktop()` returns owned scalar/category data:

- the **current process's** Windows session ID;
- the current thread's desktop category;
- the input desktop category as opened for the process's window station.

Only `Default`, `Winlogon`, or `Other(redacted)` classifications leave the module.
Other desktop names are never retained in the public result or printed. Invalid
UTF-16 produces an explicit error, never hidden replacement characters. A desktop
named `Winlogon` does not establish a UAC prompt, authenticated prompt origin,
authorization, successful Windows authentication, or permission to act. The
separate queries are not an atomic desktop-state snapshot.

The process session is not automatically the active console session or the target
user's logon identity. `ProcessIdToSessionId` queries the supplied process; the
observer supplies only its own process ID. It does not query another process or
alter its token. [Microsoft process/session contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-processidtosessionid)

Input-desktop opening requires an input-capable associated window station;
disconnected-session behavior can refer to the desktop used after reconnection.
Failures from a noninteractive service, access denial, locked/secure desktops or
other Windows conditions are returned, without elevation, polling or policy
fallback. [Microsoft OpenInputDesktop contract](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-openinputdesktop)

## Handle and FFI invariants

`src/ffi.rs` is the only first-party unsafe boundary and is compiled only on
Windows. Every unsafe block has a local `SAFETY` explanation. No raw `HANDLE`,
`HDESK`, pointer or name text is exported.

| Handle | Ownership | Lifetime and release |
| --- | --- | --- |
| `GetThreadDesktop(GetCurrentThreadId())` | Borrowed from the current live thread | Private thread-affine wrapper, never closed and never moved to another thread |
| `OpenInputDesktop` | Unique owned open handle | Private non-Clone/non-Copy thread-affine RAII wrapper; explicit normal-path close with error propagation, Drop release on earlier failure/unwind |

The borrowed handle must not be passed to `CloseDesktop`; independently opened
handles are the caller's release responsibility. Neither wrapper assigns a handle
to any thread. Explicit close takes its handle before the FFI call to avoid a
second close even on an error. On an earlier failure or unwind, Drop attempts
release without masking that failure; it cannot return a new error. Normal-path
release failure prevents a successful observation. [GetThreadDesktop](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getthreaddesktop), [CloseDesktop](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-closedesktop)

`OpenInputDesktop` uses zero control flags, inheritance `false`, and only
`DESKTOP_READOBJECTS`. No switch, write, enumeration, hook, security-descriptor,
generic-all or privilege-changing rights are requested. There is no
`SetThreadDesktop` or `SwitchDesktop` call. [Desktop access rights](https://learn.microsoft.com/en-us/windows/win32/winstation/desktop-security-and-access-rights)

The name query uses `GetUserObjectInformationW(UOI_NAME)` in two bounded steps.
Only the expected insufficient-buffer probe failure is accepted. An unexpected
probe success or any other failure is an error. A returned byte length must be
positive, even and at most 1024 bytes (512 UTF-16 units including NUL). This is an
application bound, not a claimed Windows limit. A fixed initialized `u16` array
provides alignment; only the bounded prefix is supplied to the synchronous FFI
call, and no pointer is retained. On success, the actual returned length must fit
that supplied buffer, followed by strict nonempty, single trailing NUL, no embedded
NUL and UTF-16 validation. No failed-call output is decoded. [GetUserObjectInformationW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getuserobjectinformationw)

The safe public result deliberately has no raw-name or raw-handle accessor. Error
diagnostics retain fixed operation/reason enums and numeric HRESULTs, not Windows
message strings, handles, names, screen contents, window titles or credentials.

## Lint and dependency boundary

The workspace's `unsafe_code = forbid` remains unchanged for shared/core crates.
This Windows-only FFI crate intentionally opts out of workspace lint inheritance
and explicitly declares `unsafe_code = deny`, `unsafe_op_in_unsafe_fn = deny`,
`missing_debug_implementations = warn`, Clippy `all = warn`, and the same
debug/todo/unimplemented restrictions. The library root also denies unsafe; only
the private `ffi` module has an allow annotation. Its bin and integration-test
roots deny unsafe as well. This exception requires the root security review.

`windows` 0.62.2 is a Windows-target-only dependency, with only `Win32_Foundation`,
`Win32_System_Threading`, `Win32_System_RemoteDesktop` and
`Win32_System_StationsAndDesktops` features. Generated bindings in the locally
cached published `windows-0.62.2` dependency were statically read to confirm
signatures: `src/Windows/Win32/System/StationsAndDesktops/mod.rs`,
`src/Windows/Win32/System/RemoteDesktop/mod.rs`, and
`src/Windows/Win32/System/Threading/mod.rs`.

Original project code is GPL-2.0-or-later. The `windows` dependency retains its
upstream MIT OR Apache-2.0 licensing and notices; none of its generated source is
copied into this crate. [windows crate metadata](https://crates.io/crates/windows/0.62.2)

## One-shot developer CLI and verification

Root's real-environment read-only check:

```text
cargo run -p windows-observer --bin uac-observe -- --once
```

No arguments also means one observation. `--help`/`-h` only prints usage. Unknown,
repeated or combined flags fail with exit code 2 without echoing their values.
Observation/output failure has a nonzero exit. Unsupported platforms return
`UnsupportedPlatform`, never a successful no-op. There is no continuous polling.

Success output is labeled `developer diagnostic; read-only; not UAC detection or
approval` and includes only platform, current-process session ID and both desktop
categories. The binary does not register services, induce UAC, capture windows,
enumerate callbacks, use UI Automation, start another process, inject input,
switch desktops, modify policy, or approve consent/credential prompts.

Written tests cover pure UTF-16/classification/byte bounds, malformed results,
redaction, argument parsing, output errors and safe compile-time API usage. They
do not query actual Windows desktops or trigger UAC. Root must run unit/doc tests,
fmt, Clippy, real Rust Analyzer and the one-shot real-environment command. These
checks cannot establish Android/Windows end-to-end behavior or a supported future
UAC action mechanism.
