# Final architecture candidate review: QR / USB button spacing

Date: 2026-09-20. Baseline: `208fc9e`. Reviewer: fresh spacing_architecture agent.
Status: ROOT approved no additional refactor. Final receipt recorded below.
No product changes by this reviewer.

Skill: `improve-codebase-architecture`; read its complete SKILL, LANGUAGE,
HTML-REPORT, project CONTEXT and ADR0036. ROOT reports fresh general Codex usage
17% used at this genuine final review phase boundary; this reviewer did not
obtain a separate usage observation.

HTML report:
`C:/Users/32170336/AppData/Local/Temp/architecture-review-20260920-024231.html`.

## Recommendation: retain existing module, no additional refactor

Strength: Strong. The only product implementation change is
`ui/src/styles.css:278`: the existing `.collection-actions` module now owns a
`--space-3` gap and wrapping. `CollectionPanels.tsx:112` already selects this
interface for the phone pairing ceremony entry controls. The same interface
also serves single-action relay-save/history rows, where a gap adds no external
padding. Locality is already correct: spacing knowledge stays in one CSS rule.

PC uses the intentional full-width stacked arrangement at
`CollectionPanels.tsx:104` and `styles.css:184`, with existing `--space-4`
spacing. Retain it rather than forcing both presentations through a new
configurable module. Existing handlers, disabled predicates, focus order and
button hit-area rules are unchanged.

Deletion test: removing the shared layout module moves its spacing/wrapping
knowledge into callers. A new module holding just the two declarations would
be shallow: its interface would be nearly as complex as its implementation.
It offers no demonstrated depth or leverage gain. The differing phone/PC
arrangements do not need a new adapter seam.

The new regression source crosses the rendered button interface in the existing
gallery (`tools/ui-gallery/gallery.spec.ts:14`), checking separation, horizontal
containment, minimum hit height and enabled Tab order. Cases cover normal,
narrow, enlarged-text and disabled PC presentation. Keep the checks in the
existing gallery rather than extract arithmetic away from the rendered layout.

## Invariants and evidence limits

- No new interface, dependency, token, authorization path or native change.
- No auth, Rust, transport, USB receiver, event handler or capability edits.
- ADR0036 protected pairing ceremony behavior remains unchanged.
- Security review PASS is recorded in adjacent `security-review.md`.
- This is static source review only; no builds/tests/fmt/lint/device QA ran here.
- ROOT must inspect actual CI geometry/artifacts; source assertions are not a
  passing execution and synthetic browser screenshots are not native proof.
- No domain or ADR update is needed for retaining the existing presentation
  module; no new domain concept or load-bearing decision is introduced.

Decision requested from ROOT: approve no additional refactor, retain the scoped
CSS fix and gallery additions, proceed to exact-commit CI and publication.

## Independent read-only exploration

The skill-requested bounded explorer `spacing_architecture_explore` confirmed
the three `.collection-actions` callers at CollectionPanels lines 95/112/141,
the separate PC arrangement, and no meaningful depth from extracting a new
action-row module. It ran no validation and edited nothing.

One optional test precision note: the common regression minimum is 0.75rem on
PC too, so it checks sufficient separation but does not specifically lock the
retained PC 1rem. No source defect or architecture change follows from that;
ROOT may choose a PC-specific minimum as a bounded test-only adjustment.

## ROOT selection and final receipt

ROOT approved retaining the one shared CSS rule and the separate PC stack, with
no new module and no additional refactor. The retained implementation has
appropriate locality; a new action-row interface would add no demonstrated
depth. This completes the bounded final architecture review.

ROOT selected two QA-only follow-ups: a PC-specific 1rem regression minimum
(phone remains 0.75rem), and read-only button-bounds/screenshots in the existing
WindowsGuiMedium and Android minified-startup CI on the connected-PC page.
Those checks must not click pairing controls, introduce mocked native state or
change product code. Their results remain ROOT's execution responsibility and
are not established by this static receipt.

No architecture implementation or domain/ADR change was required or performed.
No builds, tests, lint, format commands or native QA were run by this reviewer.
