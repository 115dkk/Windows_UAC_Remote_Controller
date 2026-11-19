<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0051: A parked UAC prompt is reported, never approved

Status: implemented source. Unit and service tests ran on the development PC;
CI builds the Android app and runs the protocol prover. Not yet observed on
hardware with the new build.

## Evidence

On 2026-11-15 at 02:44 an agent started the 1.12.1 installer with
`Start-Process -Verb RunAs` from the Claude app's windowless PowerShell. The
phone showed the PC as connected, yet no request arrived. Measured on the PC:

- consent.exe was running in session 1, and the watch helper was alive.
  `diagnostics.jsonl` had no `observed` row and no `watcher_restarted` row; the
  service kills a helper that stays silent for 15 s, so the helper was
  healthy.
- `OpenInputDesktop` named the input desktop `Default`, not `Winlogon`.
- consent.exe owned one visible top-level window per request, of class
  `$$$Secure UAP Dummy Window Class For Interim Dialog`, titled
  "<program>이(가) 사용자 권한을 요청하고 있습니다."

Windows does this when the program asking for elevation is not in the
foreground: instead of switching to the secure desktop it flashes a shield
button on the taskbar and waits for the user to click it. The helper censuses
only the `Winlogon` desktop, so it saw nothing.

Ways of waking the prompt from the PC without a person, all tried that night:
`SetForegroundWindow` (also after `AttachThreadInput`) returned false; the
taskbar button exposes no UI Automation Invoke pattern; a synthesized mouse
click landed on the button's exact centre and the input desktop stayed
`Default`. Only a real click at the PC wakes it. AGENTS.md also forbids any
input-injection API, so this ADR does not try.

## Decision

1. The watch helper, while the input desktop is not `Winlogon`, counts at most
   once a second the visible windows of that class owned by the system
   consent.exe in its own session, and sends `Parked { count }` (0..=16) to the
   service only when the count changes. A failed count keeps the previous
   value and never ends the helper, so this addition cannot stop approvals.
2. The service journals `parked_on_taskbar` (with the count) or
   `parked_cleared`, shows both in the PC history, and sends phones a new
   signed notice (`WUACNTC\0`, domain `.../pc-notice/v1`) carrying the PC
   identity, boot epoch, a sequence number and the count.
3. The notice goes only to phones that negotiated ALPN `wuac-control/3`. A
   1.12 phone aborts its session on any frame it does not know, so sending it
   to V1 or V2 phones would make them reconnect in a loop. Both sides now offer
   V3, V2, V1; address traffic that needed V2 accepts V3 too.
4. The phone shows a notice with no approve or deny control and posts an
   ordinary notification that opens the app. The notice is never a request,
   never reaches the decision path and is cleared when the PC disconnects.
   A stale notice (same boot epoch, sequence not newer) is ignored.
5. Agents must not raise a remote-approved elevation from a windowless shell
   (AGENTS.md). No foreground launch method has been verified.

## Protocol model

The notice is signed only to show it came from the paired PC. It carries no
request binding and cannot approve or deny anything, so it lies outside the
request and lease models. The Tamarin source bindings for `config.rs`,
`peer_runtime.rs` and `watch.rs` were re-hashed with a review section in
`security/tamarin/README.md`; no theorem, rule, canary or expected verdict
changed.

## Consequences

- A parked prompt still has to be clicked at the PC. The phone now says so
  instead of staying silent.
- A 1.13 PC with a 1.12 phone behaves exactly as before: no notice.
- The helper does one extra window enumeration per second while the user's
  desktop is in front.

## Amendment, 2026-11-19: the census never ran on a real desktop

On 2026-11-19 two `Editor.exe` prompts were parked on the development PC
(18:35:11 and 18:44:43, the first one second after an approval from the phone
had been applied) and the phone, connected over V3, showed nothing.
`diagnostics.jsonl` held no `parked_on_taskbar` row since 1.13.0 was installed.
The helper enumerated every top-level window of the `Default` desktop under
`MAX_TOP_LEVEL_WINDOWS` (128), a limit chosen for the Winlogon desktop; that
desktop held 447 windows, so every census failed and decision 1 kept the count
at 0. The census now collects only windows of the parked class, whatever the
number of other windows. A unit test enumerates the test's own desktop and, when
it holds more than 128 windows, also shows the old enumeration failing there.
Not yet observed with an installed build.
