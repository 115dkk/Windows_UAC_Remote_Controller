# Controller UX contract

Status: new high-consequence installed UI in development. No end-to-end remote
UAC approval or credential entry is yet proven. Full user scope remains active.

## Baseline, users and ownership

Baseline evidence: the repository previously had tested Rust libraries and a
read-only Windows desktop probe, but no UI. The user wants infrequent Windows
setup/management and frequent quick phone decisions. Korean, Windows 11 and
Android phone operation are explicit; other languages/tablet-specific layouts
are not promised in this increment. Larger text, keyboard use and poor
connectivity are material counterexamples, not assumed uncommon users.

| Owner | Responsibility |
| --- | --- |
| React/HTML client | Navigation, inert text, editable drafts, disclosure, focus and presentation |
| Tauri native shell | Window/provider/lifecycle, narrow commands, app-private path discovery |
| Rust controller runtime | Validated settings persistence, snapshot/command orchestration and error translation |
| Windows SCM/service/native modules | Actual service state, privilege checks, key protection and eventual prompt action |
| Android Kotlin + Rust | Actual secure-lock/authentication/notification/intent behavior and request policy |

No UI boolean, toast, queued callback or animation grants approval. Native
credential values, keys and QR bootstrap secrets must not enter WebView state.

## Journeys and state truth

1. Windows launch → read actual service state → show initial setup or current
   state → user chooses one allowed fixed management action → Windows elevation
   and helper outcome → refresh native state. Running alone does not mean paired
   or ready to receive remote decisions. UAC cancellation preserves the old state.
2. Phone launch → distinguish configured/missing/unavailable screen lock → show
   requests or an empty state → show PC/program/path → optional full details →
   native authentication on approval only → wait for Windows result. Pending
   and completed are distinct; stale requests cannot remain actionable.
3. Phone notification settings → edit days/windows/alert mode → save to Rust →
   show saved state. No configured schedule means always; explicit disabled
   means never. Outside-hours requests are discarded by Rust, not deferred by UI.
4. Connected device and activity navigation → show real owner data or honest
   empty/error state. Unpair/remove/clear are only available when owner supports
   them and after appropriate confirmation. They are not simulated mutations.

Loading does not briefly display a missing-lock warning. Readiness error must
not ask a correctly locked phone to create a lock. Failed refresh preserves
labelled stale information, disables unsafe stale actions and offers refresh.
Save failures preserve the user's draft. Repeated clicks do not duplicate native
commands. Windows/helper errors are translated; raw codes never appear in the
phone UI. Exit from detail/dialog restores task context and focus.

## Capability staging

This increment wires actual service-status reads and local validated policy
storage. Service management becomes available only through a validated fixed
helper and its native checks. Pairing, real request delivery, credential entry,
phone signing, removal and service-history access must remain unavailable until
their real owners are connected. Passive empty-state signposts may exist; no
enabled placeholder buttons or fabricated success. This is incomplete product
work, not accepted UX debt or a smaller definition of the finished goal.

Production entry imports no mock data. A separate QA entry may render synthetic
states with production-built components; it is not packaged as the application
and its artifacts are labelled simulated client-state evidence.

## Spatial and input contract

- Windows native caption owns move/resize/snap/minimize/maximize/close. Main
  content scrolls independently of a stable navigation rail. No custom caption.
- Phone uses a visible location and stable bottom navigation. Primary request
  actions remain reachable without covering details or the on-screen keyboard.
- Program/path are summary output; command details are on demand and remain
  inert, wrapped, selectable text. Original program strings are not translated.
- Semantic/read/focus order follows task order. Details, confirmations and field
  errors have meaningful accessible names; no decorative focus stops.
- Forms support IME composition, keyboard selection, save/cancel and validation
  after commit. Do not submit incomplete composition.
- Responsive layout preserves every applicable action at native minimum sizes,
  phone portrait/landscape, 200% zoom/text scaling and long Korean/unbroken text.
- Reduced motion preserves state/focus without waiting for animation. OS-native
  permission/authentication animations are not replaced by CSS.

## Korean content and consequences

RC-1: no empty safety/accuracy assurances. RC-2: errors state outcome or next step.
RC-3: prefer a useful next action without erasing truthful limits. RC-4: every
behavior/retention/recovery claim maps to implemented owner behavior. The root
applies humanize-korean semantic review after copy is written. English internal
event names, failure codes and abbreviations do not become Android labels.

## Traceability and proof owners

| Clause | Implementation | Root proof |
| --- | --- | --- |
| Presentation/disabled actions | ui/src components + contracts.ts | UI behavior tests, browser accessibility/interaction and rendered captures |
| Actual snapshots and settings | controller-runtime + src-tauri commands | Rust tests, native launch/bridge observation and persistence checks |
| Service commands | windows-service-host | root source review, native read-only check; actual elevated lifecycle separately |
| Device lock/auth/notification | native Kotlin plugin + Rust | Android build plus emulator/device checks; never browser-only proof |
| Prompt approval/credentials | eventual Windows adapter + phone crypto | exact live prompt, authentication, expiry/race and real target evidence |

UI run: `.superloopy/evidence/frontend/20260908T133939Z-controller-shell/`.
Each surface-evidence row names one target + owner (browser/client, native shell
or hybrid bridge) and its own artifact. Browser screenshots cannot prove native
permission, packaging, biometric or UAC behavior. Root checks production build,
affected/adjacent journeys, focus, long text, theme, reduced motion and relevant
window bounds. Native/Android limitations remain unverified until exercised.

No usability/prevalence claims are inferred from a reviewer walkthrough. Root
records task context, observed friction, artifact and limitation rather than
claiming that all users find the interface easy or premium.
