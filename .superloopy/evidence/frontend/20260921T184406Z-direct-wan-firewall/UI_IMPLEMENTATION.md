# UI implementation receipt

Implemented by direct_ui; ROOT owns all executable checks and release work.
No build, test, lint, format, executable check, screenshot or device QA was run
by this child. Source-only inspection informed this receipt.
Loop links: G006/C001 and G006/C002, supporting evidence only, not marked pass.

FRONTEND_SKILL_DIR:
`C:/Users/32170336/.codex/plugins/cache/beefiker/superloopy/0.19.0/skills/superloopy-frontend`

Selected references: shared UX, Web, desktop, mobile, hybrid and layout;
reassurance-copy RC1–4; make-interfaces-feel-better full scoped review.
Existing-system direction and CSS tokens remain authoritative. Skill routing
requires ROOT rendered and native evidence before capability promotion.

## Changed files

- `ui/src/directConnection.ts`: pure presentation gates for fresh/unknown/stopped.
- `ui/src/DirectConnectionStatus.tsx`: neutral external state and scoped program
  connection guidance, with existing `supporting-text` style.
- `ui/src/contracts.ts`: optional native `internetState`, no command API.
- `ui/src/App.tsx`, `StatusPanels.tsx`, `CollectionPanels.tsx`: output placement and
  explicit client-stale propagation; remove outdated same-network/manual-relay
  default paragraph while preserving advanced relay form.
- `ui/src/RequestPanel.tsx`: PC prompt guidance only in known disconnected context.
- `locales/*.json`: nine messages in all eleven locales from first implementation;
  product names match current locale names, executable spelling stays literal.
- `ui/src/styles.css`, `DESIGN.md`: existing spacing/type roles only.
- `DirectConnectionStatus.test.tsx`: DTO gates, missing/null, stale refresh on
  both PC tabs, actual LAN connection separation, locale and phone recovery.
- `qa-fixtures.ts`, `tools/ui-gallery/direct-connection-{cases.ts,spec.ts}`,
  `declared-cases.ts`: twenty registered synthetic client-gallery cases.
- `RelayStatus.test.tsx`, `tools/ui-gallery/gallery.spec.ts`: listener selectors
  scoped to avoid confusing separate external-state output with relay output.
- `RelayStatusLine.tsx`: shared fresh/live-listener gate and explicit stale flag
  also withdraw old listener success, avoiding a stale green sibling output.
- `playwright.gallery.config.ts`: ROOT explicitly authorized the one-line test
  allowlist addition for `direct-connection.spec.ts`.

## Scoped polish review (full)

| Category | Source inspected | Result |
| --- | --- | --- |
| Typography | Existing paragraph/supporting-text rules, new outputs | Wrapped text, no fixed height; actual rendering pending |
| Surfaces | Existing service/auxiliary card and phone notice | Reused normal-flow regions; no new nested card/token |
| Animations | New component/CSS | None introduced; motion inspection N/A |
| Icons | Existing listener/phone notice | No added icon; candidate gets no success glyph |
| Performance | Added synchronous enum selection | No polling/effect/network owner introduced; measured performance unverified |
| Color | Existing supporting-text role | Candidate stays muted, no success/warning claim; rendered contrast pending |
| Interruptions | Passive output/phone notice | No takeover, action, countdown or focus change |
| Qt | React/Tauri implementation | N/A |

| Severity | Location | Before | After | Why |
| --- | --- | --- | --- | --- |
| HIGH | PC external route output | No route observation; manual external-relay guidance | Native enum with fresh/stale gates and neutral candidate | Functional truth: listener/LAN peer does not prove external connection |
| MEDIUM | PC/phone connection recovery | No program-specific V3 prompt guidance | Conditional instructions name the product and executable | Contextual recovery without broad firewall permission |

Considered and rejected: success-colored candidate (not a completed connection),
global warning/takeover (no current failure evidence), new setup CTA (would alter
default path), fixed-height compact guidance (would clip enlarged translations).

Verdict: source implementation ready for ROOT review/CI. Visual, keyboard,
native accessibility, provider, package and physical-device results remain
unverified. `VISUAL_QA.md` must be authored from ROOT's actual captured artifacts.
