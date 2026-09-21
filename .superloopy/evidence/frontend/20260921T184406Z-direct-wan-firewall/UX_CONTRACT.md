# Direct-network status and firewall guidance

Status: implementation/static source review only. ROOT owns CI validation,
rendered artifact review, loop evidence attachment and native promotion.
Active loop: G006/C001 (whole-product journey, physical authentication remains
unmet) and G006/C002 (regressions). This slice is supporting implementation and
planned evidence, not a pass for either criterion.

## Scope, authority and baseline

- Existing-system delta for the installed React 19.2.8 / Tauri 2.11 client.
  Windows uses WebView2; Android 16 uses its provider WebView/native host.
  Exact deployed OS/provider build and package commit remain ROOT evidence fields.
- Authoritative design: `DESIGN.md`, `ui/src/styles.css`, existing catalogue and
  SVG system. No generated reference or new visual direction is required.
- Baseline source: `ServicePanel` shows phone/listener state; `DevicesPanel`
  owns embedded configuration and the separate external-relay draft;
  `RequestContents` has a paired-disconnected notice. Representative target
  baseline reproduction is pending ROOT; source inspection is not a screenshot.
- Primary user job (supplied/high confidence): understand whether the PC has an
  external address candidate and which program to allow when V3/firewall asks.
  Actual mobile-network reachability is unknown until exercised on real devices.
- Adjacent jobs: QR/USB pairing, local service controls, external-relay editing,
  connected-phone display and Android request review. These retain their owners.
- Out of scope: decision-feedback redesign, native authentication, firewall
  policy mutation, paid relay/account provisioning, credential entry.

## Journey and ownership

| Entry / output | Owner and lifetime | Result / recovery |
| --- | --- | --- |
| PC status or phone management | React consumes the current native snapshot | Neutral external-network status under listener output |
| Native external discovery state | Windows service; optional `relayStatus.internetState` | Missing/legacy result remains unknown; refresh PC status |
| Candidate address observation | Windows service, presentation-only React output | Ask for mobile-data connection check; never Internet/TLS/UAC success |
| V3/firewall prompt guidance | React authored copy; actual prompt and permission remain OS/security-software owned | Verify product service and `uac-service.exe`, then allow that program only |
| Known paired Android disconnection | Ready native request catalogue plus local service | Existing recovery notice gains PC firewall-prompt check |
| Advanced external-relay draft | Existing `DevicesPanel` state and native setRelay command | Retained editable draft and existing native admission rules |

The new capability is `output`, applicable to Windows direct-network status and
Android disconnected recovery, production-fidelity presentation, passive,
not invocable. Availability follows snapshot freshness; verification is
unverified until ROOT artifacts. Gallery data is explicitly simulated and cannot
promote service behavior. Undo/persistence are N/A: this delta adds no mutation
or durable client setting.

## State and invariants

1. Candidate requires Windows, embedded/listening, installed/running service,
   available control owner, available device inventory and a non-stale current
   client read. Native unknown takes precedence over cached stopped SCM state.
2. Missing/null optional state maps to unknown. Stopped service/listener maps to
   stopped only when the relay read is not unknown. Legacy services keep their
   existing device visibility, controlled by native integration, not this output.
3. Discovering, LAN-only, candidate, unavailable, stopped and unknown are distinct
   authored outputs. Neither LAN-only nor candidate asserts a successful
   connection. A connected LAN peer cannot change the external state or color.
4. A failed refresh preserves the existing snapshot for other established UI,
   but its `stale` flag forces this output to unknown and hides firewall guidance.
   Existing listener output also withdraws its success styling on stale reads
   or unavailable device inventory using the same live-listener predicate.
5. Firewall guidance is conditional, names the executable, and grants no new UI
   action. It never asks to disable firewall software or allow all applications.
6. Android recovery appears only inside a known paired-disconnected notice,
   with a ready catalogue, local settings-ready service and non-disabled client.
   No hint is inferred from unknown/unread inventory, no peers, pending requests
   or a connected empty request list.
7. No new secrets, endpoint coordinates, input field, analytics, URL, command or
   bridge capability is exposed. Existing external-relay form stays intact.

## Spatial, accessibility and localization contract

- Place the passive Windows output below the existing listener status, in normal
  DOM/main-scroll order; no disclosure, modal, sticky region or extra focus stop.
- Existing main page owns scrolling. Paragraphs wrap without fixed-height
  clipping; existing 42rem rail transition, 52rem padding and phone breakpoints
  remain authoritative. Input/control targets are untouched.
- Native service and client status are separate semantic outputs. New status
  uses `role=status`; guidance is ordinary supporting text, not an alarm/live
  region. Update does not move focus. Candidate uses no success glyph/color.
- All 9 new authored messages ship in all11 catalogues. Existing localized
  product names and literal executable identifier are preserved; Arabic follows
  existing page direction. New paragraphs use existing Korean word wrapping.
- Coverage: Windows760 minimum,390 client stress; ko/de/ar200% root-text stress;
  Android320 and390/200%; candidate across all11 languages. These are planned
  client evidence cases, not OS scaling/device proof. Keyboard and scroll
  reachability of the adjacent advanced form are included.
- Native screen-reader/provider semantics, real firewall permissions and actual
  phone/UAC completion remain independently unverified. SEO is N/A for installed
  embedded clients; no new public Web deployment.

## Decisions and content review

Decision: retain inline neutral output instead of a success badge or global
warning. Authority: supplied candidate semantics and existing status hierarchy.
Warrant: source keeps connection and candidate owners independent. Limitation:
readability and task success still require ROOT rendered/real-target evidence.
Rejected alternatives: takeover would interrupt an unrelated task; adding an
external-relay setup CTA would change the supplied default path.

RC-1: no safety/accuracy reassurance. RC-2: unavailable state names network
settings; unknown names refresh; stopped names service start. RC-3: neutral
observation/next-action wording; LAN-only does not promise connectivity. RC-4:
recovery references existing PC status/service controls and user-supplied V3
prompt guidance, with no invented recovery outcome. Humanize Korean semantic
review retained formal product register and protected `V3`, `UAC`, and
`uac-service.exe`; no semantic accuracy claim was added.

## Traceability and proof plan

| Clause | Implementation | Acceptance / ROOT artifact |
| --- | --- | --- |
| Fresh/stale/missing/stopped gates | `directConnection.ts`, `App.tsx`, status/collection panels | `DirectConnectionStatus.test.tsx`; CI unit log |
| Candidate not actual connection | `DirectConnectionStatus.tsx`, `directConnection.ts` | LAN-peer regression; candidate gallery captures |
| Contextual firewall recovery | `DirectConnectionStatus.tsx`, `RequestPanel.tsx`, `locales/*.json` | Conditional presence/absence tests; Android320/200% gallery |
| Reflow and adjacent form | Existing CSS tokens, `direct-connection-cases.ts` | `direct-connection.spec.ts`, captures and geometry assertions |
| Existing relay state | `RelayStatus.test.tsx`, `gallery.spec.ts` selector scoped to listener | Existing regression suites |
| Native observation/legacy fallback | ROOT Windows native integration | ROOT actual CI/native owner artifacts, independent from client |

| Target | Owner | Claims | Scope reason / evidence status |
| --- | --- | --- | --- |
| `windows-client`, Windows, installed Tauri/WebView2 | client | Current-state wording, neutral candidate, layout/focus/reflow | Changed output; CI gallery/test artifacts pending |
| `android-client`, Android16, installed Tauri/WebView | client | Disconnected recovery wording and narrow/text-scale layout | Changed visible recovery paragraph; artifacts pending |
| `windows-native`, Windows, installed native service/host | native | Read-only direct state correctly reaches current snapshot | Native producer changed outside this slice; ROOT proof pending |

No accepted UX debt is asserted. Real firewall outcome, mobile-network reachability,
native accessibility and physical authentication are unverified capability claims,
not a passing gallery result. ROOT supplies the actual loop goal/criterion IDs and
`VISUAL_QA.md` after reviewing produced artifacts.

Native discovery scope supplied by ROOT: PCP mapping plus read-only UPnP/NAT-PMP
discovery and IPv6 candidates. No copy promises mapping on every router or
automatic UPnP changes. Candidate output never establishes mobile-WAN reachability.
