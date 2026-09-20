# P1 consent-target binding correction

Date: 2026-09-14. Source-only worker update; no validation was executed locally.

The former basename-only target check was removed. Initial approval now requires
an actual dedicated Program location/프로그램 위치 UIA label followed by a distinct
Text field under the same authenticated consent.exe provider parent. All three
elements must have nonempty RuntimeIds and the expected ProcessId. HWND-less
WinUI virtual elements are supported; any exposed HWND must independently map to
the same process. Arbitrary application FileDescription text cannot by itself
create this native-provider field structure or satisfy location binding.

The value must match the fixed protected installed service path exactly (case
insensitive, optional surrounding double quotes). The only permitted suffix is
` pair <64 lowercase hex>`; no alternate verb, extra argument, alternate path,
device/UNC prefix, alternate data stream, dot alias or hidden/control formatting
is admitted. Existing protected-path/reparse/owner/DACL/hash checks still apply
to that now-bound installed image. Any other pathlike/executable UI label fails.
The ordinary basename title is tolerated only as nonbinding display text.

Collapsed details are expanded through exactly one actual provider-bound Show
more details action. That action cannot approve. Approval still requires one
fresh System32 consent process in the fixed isolated session and one native Yes
button; it is consumed once before invocation. No AppInfo parent attribution,
UAC policy change, credential handling or generic approval command was added.

On unsupported field layout or conflicting path, failure-only diagnostics expose
fixed flags (location label, expected path, closed pair, conflicting path), Text
control type, allowlisted short AutomationId tokens and hashed node/parent
RuntimeIds. They never include raw UI text, paths, command lines, argument values,
pending identifiers, QR pixels or comparison codes. Unsupported combined-text
field layouts fail and require ROOT to inspect actual CI topology before any
implementation adaptation.

`ConsentTarget.Tests.cs` adds pure adversarial recognizer fixtures, including a
same-basename executable outside Program Files, fake Program location description,
different verbs, trailing arguments, invalid nonce shape, path aliases, ADS,
hidden formatting and malformed quoting. CI build produces
`uac-ci-consent-target-tests.exe`; ROOT must run that executable in CI and obtain
the real native UI evidence separately. Passing pure fixtures is not evidence
that a real UAC location field was recognized or approved.
