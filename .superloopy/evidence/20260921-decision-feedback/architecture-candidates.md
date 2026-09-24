<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Final architecture candidates — 2026-09-21

Status: ROOT approved A in `architecture-approval.md`; implemented and statically
reviewed. ROOT/CI validation pending. Candidate-first report retained below.

Scope: completed task delta against `edfeeb204694ea4ffc1fed411247e9bbcc711729`.
Skill: `improve-codebase-architecture`; main reviewer read LANGUAGE, HTML-REPORT,
CONTEXT, and ADR0001/0010/0011/0012/0014/0021/0032. One read-only explorer reviewed
release-note and latency changes. No child validation or source edits occurred.

HTML: `C:/Users/32170336/AppData/Local/Temp/architecture-review-20260921-181823.html`.

## A — Deepen diagnostic-save Module (Worth exploring; recommended)

Files: `AndroidDiagnosticExporter.kt`, `DeviceStateActivityCommands.kt`,
`AndroidDiagnosticSaveInstrumentationTest.kt`,
`tools/android-diagnostic-export-contract.test.mjs`.

The Interface currently makes both the physical Activity Adapter
(`DeviceStateActivityCommands.kt:596`) and native instrumentation Adapter
(`AndroidDiagnosticSaveInstrumentationTest.kt:113`) register/retain the picker,
route its result and unregister on retirement. The test duplicates the product's
picker lifecycle while exercising the real provider and existing SaveOperation.

Deepen the existing diagnostic-export Implementation to own that lifecycle;
physical-origin validity remains an observation of the original Activity Adapter.
Deletion test: remove duplicated orchestration and complexity concentrates in
one Module; deleting the existing SaveOperation would redistribute bounded
capture/write/lease complexity. This earns Locality and Leverage with two actual
Adapters, not a hypothetical general storage Seam. No interface design selected yet.

Preserve: global Save/Share lease; native-only URI/contents; immutable physical
origin; no late success after retirement; original write deadline; retained lease
for outstanding provider I/O; no deletion of user-selected documents; fixed
Saved/Cancelled/Unavailable outcomes; native guarded CI coverage. No auth,
Request lifetime, Decision semantics, Share behavior or release gate changes.

## No second production refactor recommended

`tools/release-notes.mjs:22,36,80` already concentrates published-ancestor selection,
exact checkout/tag/range checks and bounded rendering. Its real-Git tests cross
the production Interface. Splitting this into more Modules reduces Locality.

`tools/ci-phone-fixture/src/session.rs:173–207` measures at actual signed-result
observation; `tools/windows-full-pairing-lab.mjs:150–156` checks its closed receipt.
One producer/consumer does not justify a generic metrics Seam. Keep native scope
and synthetic-phone distinction explicit; measurement is not approval UX proof.

ROOT: select A or retain the current architecture. Candidate A is the only
proportional improvement. Validation remains ROOT/CI-owned.
