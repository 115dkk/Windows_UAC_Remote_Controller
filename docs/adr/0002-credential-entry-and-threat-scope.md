# ADR-0002: Preserve Windows authentication during remote credential entry

Status: accepted user direction, 2026-09-08; native feasibility still unproven.

## User decisions

1. Evaluate entering Windows-required credentials from the phone. Implement it
   if appropriate; ignore credential prompt types that cannot be handled
   appropriately. Do not replace Windows authentication with phone app approval.
2. Exclude an already-compromised SYSTEM/kernel from the threat model. Do not
   repeatedly block implementation on that excluded scenario. Unelevated local
   malware exploiting this service remains in scope.

## Candidate implementation, not an established capability

An installed privileged service and per-session native helper can be evaluated
for interaction with the existing Secure Desktop. RustDesk's source uses
`OpenInputDesktop`/`SetThreadDesktop` and ultimately character input through
`SendInput`. These are references for investigation, not a narrowly
request-bound approval API or a design to copy with all its access rights.
[RustDesk native source](https://github.com/rustdesk/rustdesk/blob/master/src/platform/windows.cc),
[RustDesk input source](https://github.com/rustdesk/rustdesk/blob/master/libs/enigo/src/win/win_impl.rs).

Username/password fields and PC PIN fields are candidates only when Windows
actually offers them. Phone biometrics or the phone PIN do not substitute for a
PC credential. PC-only sensor/card/touch requirements must not be simulated or
bypassed. Unknown/inappropriate providers are ignored, not passed to a generic
keyboard or process-execution endpoint.

User credential input must remain transient, excluded from WebView state,
telemetry, logs, clipboard, saved instance state and screenshots. Native input,
bounded zeroizing buffers and authenticated end-to-end transport need their own
implementation and tests. PC input must be bound to the same live verified
request, including cancellation/replacement races. Phone OS authentication is
still required when submitting an approval operation. Windows decides whether
the entered credentials succeed.

The Windows Secure Desktop clipboard restriction is not an obstacle to be
disabled; clipboard delivery is not the intended mechanism.
[Microsoft clipboard restriction](https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-security/file-system-error-when-pasting-password).

## Completion conditions

Record which provider/field combinations were actually exercised, with synthetic
credentials in an isolated environment. Check cancellation, timeout, new prompt,
session switch, incorrect credentials, transport loss and discarded secret
buffers. Do not ship a credential route based solely on reading RustDesk source.
The initial `windows-observer` slice reads desktop metadata only and performs
neither input nor desktop switching; it cannot satisfy this ADR's input proof.
