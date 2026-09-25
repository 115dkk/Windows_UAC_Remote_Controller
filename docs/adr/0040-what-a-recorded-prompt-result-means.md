<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0040: What a recorded prompt result means

Status: implemented, 2026-09-26. Records existing behavior; no code changed.

## Decision

After the phone's signed decision is accepted, the interactive helper presses
the dialog's button through UI Automation and then watches the dialog for two
seconds (`OUTCOME_WINDOW` in `windows-prompt-probe/src/ffi/watch.rs`, checked
every 100 ms). The service records what it saw, and only that:

| Helper outcome | Recorded result | What was observed |
| --- | --- | --- |
| `Gone` after pressing the approve button | Approved | The button was pressed and the tracked dialog left the secure desktop within two seconds. |
| `Gone` after pressing the deny button | Denied | The same, for the deny button. |
| `StillPresent` | Failed (unknown) | The button was pressed and the dialog was still there after two seconds. |
| `Refused(reason)` | Failed (rejected) | The helper did not press anything, because the dialog, its content or its buttons no longer matched what the phone approved. The reason goes to public diagnostics. |

The mapping lives in `peer_runtime.rs` (`WatchEvent::Applied`). "Gone" also
covers the input desktop no longer being Winlogon.

## What "Approved" does not establish

It does not establish that the requested program started elevated. Windows
does not tell a third party what `consent.exe` returned, and the product does
not watch process creation. The recorded result therefore cannot tell these
apart from a real approval:

- someone at the PC pressed a button, or Esc, in the same two seconds;
- the program started elevated and then failed, or AppInfo failed after consent.

A dialog that closes without anyone pressing a button (timeout, the requesting
program exiting) is recorded as cancelled, not approved, because the helper
reports it as a disappearance before any apply.

## Why not verify the launch

Correlating the result with a new elevated process would need process-creation
observation (ETW or a job/snapshot diff) and a match on image path and parent,
which appinfo does not expose for the requesting program. It would add a
privileged observer for a claim the user can see on the PC anyway, and it could
not be measured here: no new personal-PC UAC experiment is authorized. If it is
ever added, it should be a separate result ("launched") rather than a stricter
meaning of "Approved".
