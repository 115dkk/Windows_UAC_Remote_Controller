# Read-only Windows consent-UI capability probe

This crate is a **diagnostic probe, not a request identity or approval adapter**.
The safe outward API is `probe_once() -> Result<ProbeReport, ProbeError>`, with no
caller-selected process, HWND, path, session, desktop, property, input or action.
The helper binary `uac-prompt-probe` accepts no arguments. Other arguments fail
without echoing them. No service launcher, installation, supervision, elevation,
registration, token adjustment, policy change, network or user-input endpoint is
implemented here.

ROOT must integrate a fixed, protected installed helper and a separately reviewed
five-second process supervisor before privileged use. No workspace executable is
automatically installed or launched by this crate. A Session-0 service does not
become a per-session SYSTEM UI process merely because the service is Running.

## Exact supported observation profile

Before UIA, native calls verify no thread impersonation (only actual ERROR_NO_TOKEN
means absence), a LocalSystem process TokenUser, exact system-integrity SID, matching
nonzero token/process session and a visible `WinSta0` process window station.
Native 64-bit AMD64/ARM64 processes are supported; WOW/emulated/other profiles are
explicitly unsupported. Query errors do not trigger token, permission or machine
fallbacks. No privileges are enabled and no restrictive SID is removed.

The parent opens the actual input desktop noninheritable with READOBJECTS only.
Input status and the `Winlogon` category are prerequisites, not proof of UAC. It
keeps its desktop owner alive while a fresh scoped worker assigns that same
desktop before creating a windowless MTA/Windows UIA client. Borrowed process,
thread and window-station handles are never closed.

The private cross-thread desktop token carries only an opaque Windows handle
value under the scoped parent lifetime. It is never a Rust pointer dereference,
public API or `unsafe impl Send/Sync` for a broad handle. All worker interfaces,
tokens and process handles are dropped on their owning worker; the parent waits
for actual worker exit before closing its separately opened desktop handle.

Enumeration inspects at most 128 top-level windows on that held desktop. A unique
candidate must have an OS-reported image path matching the OS-resolved system
directory plus `consent.exe`, native64 architecture, SYSTEM/system-IL token,
matching session, retained query/synchronize process handle, creation time and
unsignaled process state. HWND thread/PID, process facts/image/liveness and desktop
input state are rechecked around the UIA traversal. Unknown/inaccessible/racing
observations and multiple candidates fail rather than guessing.

**This path comparison assumes the intact OS/system directory. It is not a full
mapped-image hash/Authenticode proof. The consent UI process is not the executable
being elevated. These checks do not provide atomic elevation-request identity,
an immutable original command, or a race-free later action target.** The future
launcher must independently prove the intended session and protected helper.

## UIA, bounds and prohibited data/actions

The client is scoped to `ElementFromHandle(candidate)`, never the whole desktop
tree. It requires UIA2 connection and transaction timeout support, configuring
each to 1,000ms. Traversal allows at most 128 inspected elements and depth 16
(root depth one). Password flags are read first; password nodes and descendants
are skipped. Other reads are fixed control type, owner PID, native HWND,
enabled/offscreen flags and three pattern-availability booleans (Invoke, Value,
legacy accessibility). No actual action-pattern interface is obtained.

There is **no UIA Name/Text/Value or credential-value read**, AutomationId dump,
window caption, command line, screenshot, clipboard, ValuePattern write, window
activation, Invoke, BM_CLICK, WM_COMMAND, SendInput or arbitrary-message API.
Desktop/window-station object names are private diagnostic prerequisites only.
Output exposes only fixed statuses/counts and fixed error categories/numeric
HRESULTs; no PID, handle, path, raw name or provider content escapes.

Raw tree-walker vtable calls deliberately preserve the native distinction between
S_OK with a null element (normal end-of-tree) and an actual HRESULT failure such
as E_POINTER. The windows-rs convenience wrapper turns null interface conversion
into an error; treating that error code as absence could hide a real provider
failure. Only successful nonnull AddRef-owned interface output is adopted. Callback
and pointer boundaries document their lifetime/ownership invariants inline.

Cooperative five-second checks and UIA's timeout settings are **not a hard bound**:
native/provider calls, COM release and apartment teardown can block. The function
joins its worker fully; it never reports a timed-out join as successful termination
or emits observations while the worker continues. The mandatory future process
supervisor must bound/terminate the complete helper, not `consent.exe`.

## Cleanup and output

Every owned token/process/desktop and property VARIANT logs observed release
failures into a bounded shared summary. The original failure remains primary;
first cleanup operation/HRESULT and cleanup-failure count remain attached. A clean
operation with failed cleanup becomes an error, never a capability report. COM
Release/CoUninitialize expose no HRESULT and are not labelled successfully timed.

Normal success/error output occurs only after worker completion and resource
scopes. On observed native cleanup failure, the binary emits no report and returns
exit 3 so process teardown completes outstanding OS cleanup. The library error
still preserves both causes. The dedicated binary silences raw panic payloads;
the library does not replace a host panic hook. Windows/API/worker failures return
nonzero; argument rejection returns 2. Successful metadata is not authorization.

## Source/test boundary

First-party unsafe is isolated under the Windows-only `ffi` module tree; shared
policy and binary code forbid unsafe. Non-Windows returns UnsupportedPlatform;
32-bit Windows returns Native64Unsupported without native observation.

Authored tests exercise API shape, pure bounds/SID/name parsing, error precedence
and non-Windows unsupported behavior only. **No Windows test calls probe_once or
the helper**, including assumptions that a developer token is not SYSTEM. No
native capability or privileged launch has been exercised by the child.

ROOT owns Cargo integration, formatting, all-target/all-feature Clippy with
`-D warnings`, actual Rust Analyzer, tests and independent static FFI review.
Native privileged launch/UAC remains user-deferred. No service launch is wired.

Source basis: the existing
`.superloopy/evidence/secure-desktop-next-probe.md` design and installed
windows-rs 0.62.2 signatures/ownership implementations. Original project code is
GPL-2.0-or-later; dependency notices remain their own.
