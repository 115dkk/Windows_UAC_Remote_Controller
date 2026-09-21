<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Final architecture result — 2026-09-21

ROOT selected candidate A and approved the posted-launch design and exact
disposable-emulator Downloads-file observation. No other candidate implemented.

## Implemented scope

- `AndroidDiagnosticExporter.kt`: existing diagnostic-save Module now owns
  the unique ActivityResult registration, fixed document intent, result handling,
  launcher retirement and terminal unregistration. Admission posts launch so the
  original physical Adapter installs its operation slot before any completion.
  Current-origin observation and foreground observation are separate: covering
  the app with the document picker does not cancel a valid originating Activity.
- `DeviceStateActivityCommands.kt`: retains the physical Activity/WebView
  observation and no-argument intent/reply mapping. Its one operation handle
  replaces the separate launcher. No picker orchestration remains here.
- `AndroidDiagnosticSaveInstrumentationTest.kt`: calls the same production
  Interface; duplicated picker/result registration is removed. The actual system
  picker selects Downloads and a unique synthetic name; only the exact generated
  path is read through a bounded emulator shell command after native Saved.
- `tools/android-diagnostic-export-contract.test.mjs`: guards the new ownership,
  distinct current-origin check, shared production Interface and bounded native
  file observation, retaining no-arguments/permissions/CI requirements.

## Static invariant review

The global Save/Share lease, closed diagnostic capture/filtering, original
provider-write timeout and closed outcomes are unchanged. The lease remains
owned until outstanding provider I/O returns; retirement closes the gate before
any late success. The output stream's `use` still closes before Saved is posted.
Only ACTION_CREATE_DOCUMENT supplies the content URI; no renderer data, broad
permission, generic storage abstraction or selected-document deletion is added.
Unique registration and the captured original-host check prevent adopting a late
result into a replacement physical Adapter. Request lifetimes, native
authentication, signed Decision handling and release gates are unchanged.

Native UI selection expects the guarded AVD's English DocumentsUI (`Show roots`
and `Downloads`); those observations fail closed. Exact CI must establish that
the image exposes those real nodes. The generated name is validated before a
read-only `head -c 393217 /sdcard/Download/<name>` command. No directory listing,
unrelated-file read or test cleanup deletion occurs.

No build, test, lint, format, executable validation, commit or push was performed
by the architecture agent or its one read-only explorer. ROOT owns all CI/native
validation and any evidence-backed correction.
