# Production startup failure diagnostics

Date: 2026-09-19. Implementation owner: security_review child.
Baseline for this bounded addition: `89d8481`.

## Confirmed scope and unresolved cause

ROOT observed a Windows boot at 18:56:06 KST followed by SCM event 7024 at
18:56:15 with service-specific code `3841982471` (`0xE5000007`). Source maps stage
7 exclusively to `provision_current_process_observer`, before identity key work,
Ready, transport listeners and UAC request processing. This does not establish
a crash during a previously ready request.

The observer publisher/policy and SCM reporter are unchanged between installed
`v0.1.0-alpha.36` (`89c2a3e`) and `89d8481`. Its old production projection discards
the observer subphase, and SCM exposes stage 7 without `StartupFailure.detail`.
Ordinary native `WindowsCall` also becomes a generic service exit class in that
detail. The old event alone cannot identify which native call or policy condition
failed. ROOT reports the approved one-time start attempt was cancelled by the user;
no successful restart/native reproduction has been established.

**This addition fixes missing diagnostic visibility, not the underlying startup
failure. Causal repair remains pending the next actual native failure observation.**

## Implementation

- `ffi/process_observer.rs` retains a closed current subphase in a local trace.
  Every error path has a named phase, including own service SID lookup, descriptor
  drift, merged/native ACL shape, stop-before-set, publication and readback.
- On failure only, the production helper emits at most one event per service
  process to local source `UACRemoteController.Startup`, event ID 7, Error type.
  No event-source registry mutation is required. No success/milestone flood or
  retry is introduced. The event contains one <=256-byte ASCII insertion string:
  fixed schema/version, numeric process ID, stage 7, closed phase/category,
  eight-hex-digit numeric native code and closed policy reason 0..19.
- The original Windows/HRESULT numeric detail is retained when available. No
  `Display` error, OS error text, process name/path, username, SID, ACL bytes,
  credential, key or prompt content is logged. Production does not enable/reuse
  the lab ACL dump. Existing lab-only diagnostics remain lab-only.
- The policy checker now keeps a closed internal rejection enum and maps it back
  to the same existing `UnsafePermissions` result. Merge/readback admission and
  emitted ACL bytes are unchanged. A read-only diagnostic pass reuses that exact
  checker; it cannot grant access. Readback classifies changed owner/group/labels/
  control or DACL, without publishing any corresponding value.
- SCM stage 7 and its outward failure semantics remain unchanged. Event logging
  is best effort and cannot turn a rejected startup into success. No ACL relaxation,
  rollback, token/privilege edit, SCM recovery action, restart loop, delayed retry,
  protection disablement or expanded startup deadline was added.
- Native EventLog calls are synchronous, as in existing pairing diagnostics;
  count/size are bounded but this is not a claim of cancellable Windows RPC.
  Existing outer startup deadline remains in force; logging is attempted once.

## Reading the next observation

`tools/read-service-startup-diagnostics.ps1` is read-only: Application log only,
fixed source/ID XPath, 1..7-day lookback, at most 32 events (default 16), and no
service operations or file writes. XPath avoids requiring registered provider
metadata for an otherwise valid classic source.

The parser module accepts only the exact bounded schema, known phase/category,
canonical lowercase hex, nonzero u32 PID and policy index 0..19. It reconstructs
JSON fields and the OS event timestamp. Rejected text, raw Event XML, `Message`,
and exception strings never reach stdout. Query failure yields `available:false`;
no matching events yields an empty list. Records are diagnostic observations,
not trusted authorization inputs; local event-source spoofing grants no capability.

Policy indices: 0 no classified policy rejection; 1 subject shape; 2 owner;
3 ACL header; 4 ACE count; 5 ACE bounds; 6 ACE type/flags/shape; 7 SID shape;
8 interactive observer rights/duplicate; 9 trusted mask; 10 unsupported trustee;
11 missing subject control; 12 missing observer; 13 padding; 14 capacity;
15 owner changed; 16 group changed; 17 labels changed; 18 control changed;
19 DACL readback mismatch.

## Authored checks and validation boundary

Rust test sources cover numeric native cause preservation, closed diagnostic
format, phase reset, policy rejection classes and unchanged policy failure.
`tools/service-startup-diagnostics.test.mjs` exercises only pure PowerShell parser
fixtures on Windows and rejects unknown phases, out-of-range fields, oversized
input and trailing data; it neither queries EventLog nor starts a service.

This child performed static inspection and source edits only. No formatter, build,
test, lint, Rust Analyzer, script execution, service start/probe or device check
was run. ROOT owns formatting, CI, eventual installation and native readback.

API behavior references: [RegisterEventSourceW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registereventsourcew)
documents Application-log fallback without a registered message source;
[ReportEventW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reporteventw)
defines the synchronous insertion-string/SID/raw-data contract used here.
