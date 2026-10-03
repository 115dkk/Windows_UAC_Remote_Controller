<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0045: Repair from a protected copy

Status: proposed with this change. Builds on ADR 0044.

## Context

ADR 0044 made a damaged helper visible. The only remedy it offers is "reinstall
the same version", which needs the release installer, a download and a UAC
prompt that the phone cannot approve while the helper is broken. MacType's
control center shows a "repair" action for a damaged runtime; this product
needs the same, without giving unelevated malware a way to run code as an
administrator or as SYSTEM.

## What repair covers

| Situation | How it is found | What repair does |
|---|---|---|
| `uac-service.exe` or `uac-prompt-probe.exe` damaged or missing | the PC app hashes them against the repair manifest; the service's PE check (ADR 0044) | restores the file from the protected copy |
| service registration missing, disabled or drifted | SCM state | runs the restored `uac-service.exe install`, which already reapplies the whole configuration |
| service stopped | SCM state | starts it and waits for Running |
| firewall rule missing or duplicated | | `install` (it removes duplicates and re-adds one rule) |
| ProgramData activity or trust folder missing | | `install` (it provisions them) |
| torn activity journal | | nothing: the service recovers it itself (ADR 0041) |

Not repaired, and the app says what to do instead:

| Situation | Why | What the user is told |
|---|---|---|
| paired-phone registry damaged, TPM key lost | authority must never be rebuilt from a guess | pair the phone again |
| `controller-app.exe` or `uninstall.exe` damaged | not in the manifest; a broken app cannot offer repair anyway | reinstall the same version |
| the protected copy itself damaged, or its manifest missing or for another version | there is no good source left | reinstall the same version (link to the release) |

## Decision

**A protected copy ships with the product.** The installer places
`repair\uac-service.exe`, `repair\uac-prompt-probe.exe` and
`repair\repair-manifest.json` under the installation folder. The manifest holds
the product version and each file's size and SHA-256, taken from the same staged
bytes as the release manifest. The folder inherits the installation ACL:
SYSTEM and Administrators may write, users may only read and execute.

**Anyone may check, only an administrator may repair.** The PC app (user
rights) reads the manifest and hashes the installed and protected files to
decide whether to offer repair. The repair itself runs as
`<installation>\repair\uac-service.exe repair` through the existing elevated
control path, so it always passes a UAC consent prompt.

**The elevated repair takes nothing from its caller.** It accepts the fixed verb
and no other argument, reads no standard input, and derives every path from the
Program Files known folder. Before reading or writing it checks each path the
way the service checks its installation (owner, ACL, no reparse point, single
link). It refuses unless it runs as the protected copy itself, and it hashes
itself against the manifest first.

**Bytes are checked once and written from memory.** Each source file is read
into memory, hashed, and those same bytes are written to a new sibling file,
flushed, renamed over the target with write-through, reopened and hashed again.
Nothing is copied by path after it was checked.

**Repair is serialized with installation.** It holds the machine-wide
maintenance mutex that `install` holds, stops the service through the SCM before
replacing a file, and afterwards runs the restored, re-hashed
`uac-service.exe install` and `start`.

**The management pipe gains no repair command.** The service never repairs on a
client's request.

## Why this does not help malware elevate

A process with user rights can raise the repair prompt, but only as a UAC
consent for this product's own protected binary, which it could do for any
binary. If the user approves, the repair writes back only the bytes that an
administrator installed, after checking them against an administrator-written
manifest. The process cannot choose a source, a target, an argument or a
version. It cannot modify the protected copy, its manifest or the installation
folder, because they are writable only by SYSTEM and Administrators; an
attacker who already has those rights is outside the threat model (AGENTS.md).

## Consequences

- The installation grows by the size of two binaries (about 60 MB).
- A version mismatch between the protected copy and the installed product is
  refused; upgrades replace both together.
- When the service binary itself is damaged, the phone cannot approve the
  repair prompt; the user approves it on the PC.
