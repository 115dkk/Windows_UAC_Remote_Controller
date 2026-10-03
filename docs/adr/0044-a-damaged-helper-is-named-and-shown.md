<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0044: A damaged helper is named and shown

Status: implemented source with unit coverage. The detection has not yet run
against a damaged file on a real PC; the evidence below is from the PC where the
fault happened, repaired by hand before this change existed.

## Evidence

On 2026-10-03 the phone received no approval requests although it was connected
to the PC. The 1.8.0 service on that PC wrote one public diagnostic row at the
first sign-in after boot and then nothing more:

```json
{"kind":"watcher_start_failed","error":{"kind":"native","detail":{"stage":"create_child","hresult":-2147024894}}}
```

`0x80070002` is `ERROR_FILE_NOT_FOUND`, but the helper image
`C:\Program Files\휴대폰 승인\uac-prompt-probe.exe` existed with the size the
release manifest names (307,200 bytes) and the installation ACL. Its content was
307,200 zero bytes. Starting it as the signed-in user failed with
`ERROR_FILE_CORRUPT`. The service, the controller app and the uninstaller were
intact (`MZ` header present).

Measured around it, without an established mechanism:

- Kernel-Power 41 and EventLog 6008: an unexpected shutdown at 13:57:51 on
  2026-10-02. It was a bug check, not a power loss: Kernel-Power 41 records
  BugcheckCode 209 (0xD1, DRIVER_IRQL_NOT_LESS_OR_EQUAL) and volmgr 162 a
  written dump. The same PC logged ten 0xD1 bug checks since 2026-09-03, all
  with one of two faulting-address suffixes; the driver is not identified here.
- The helper had been written by the 1.8.0 install at 20:03 on 2026-10-01; the
  service started the watcher from it then without error.
- On the same PC the repository's `.git/index`, last written at 02:40 on
  2026-10-01, was also all zeros after that shutdown.

Reinstalling the same verified release replaced the file (SHA-256 matching the
release manifest) and the watcher started at once.

Three defects made a broken file look like a healthy PC:

1. The probe installation gate checks path, owner, ACL, link count and file
   identity. A zero-filled file passes all of them.
2. The watcher start is retried every minute, but a repeated refusal writes no
   new row, and the reason went only to `diagnostics.jsonl`. The app showed the
   service as running and the phone as connected.
3. The installer stops the service by running the installed `uac-service.exe
   stop`. Had the service binary been the zeroed file, reinstalling, the only
   repair, would have failed at that step.

## Decision

**The service checks the helper image before using it.** After pinning the
helper, `validate_probe_installation` reads its first page through the pinned
handle and requires a plausible PE header: `MZ`, an aligned in-page
`e_lfanew`, the `PE\0\0` signature and an AMD64 or ARM64 machine. Failure is the
new refusal `helper_damaged`, distinct from `protected_helper_unavailable`. This
is a structure check, not an integrity proof: it catches a zeroed or truncated
file, not a modified one, and Windows' own loader checks still apply.

**The app shows a watcher that is down.** The management pipe answers a new
read-only query, `QueryWatcher`, with `starting`, `running`, or `unavailable`
plus a coarse reason (`no_signed_in_user`, `helper_damaged`, `helper_failed`).
It follows the existing optional queries: older services refuse it and the app
then shows nothing. While the reason is `helper_damaged` or `helper_failed`,
every PC page shows a warning that approval requests cannot reach the phone and
what to do.

**The installer stops the service through the Service Control Manager.** It no
longer runs the installed binary for this, so a damaged `uac-service.exe` does
not block the reinstall that replaces it.

## Not in this change

- The phone is still not told. A connected phone cannot learn that the PC is
  blind; that needs a protocol message and Android UI.
- Restoring a damaged file from the PC app. A repair feature with its own trust
  rules is a separate decision.
- Flushing or verifying files at install time. The fault arrived many hours
  after the install, so a flush at install time is not supported by this
  evidence.
