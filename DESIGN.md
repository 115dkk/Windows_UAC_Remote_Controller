# Controller interface design

This is the first UI in this repository. These app-owned tokens and rules are
the visual source of truth; CSS in `ui/src` must stay synchronized. Native window
chrome, Android permission/authentication dialogs and OS insets remain native.

## Direction and authority

Installed utility for Korean-speaking Windows/Android users. Calm, compact
Windows management; a focused phone request surface with one dominant action.
The user explicitly requires Windows 11/Android conventions, no purple and no
empty safety/correctness slogans. This is not an official Fluent or Material Web
implementation. No extra component framework is adopted. React + semantic HTML
and project CSS own client appearance; native controls own OS authentication.

Design Read: a quiet installed utility, short Korean labels, restrained teal,
readable hierarchy and comfortable touch targets. This is an implementation
direction based on the brief, not evidence of user preference or usability.
No generated-image reference is necessary; actual rendered components will be
the first visual artifacts. No dashboard metrics or decorative success claims.

## Colors

| Token | Light | Dark | Role |
| --- | --- | --- | --- |
| --bg | #f2f6f7 | #101a1e | Application background |
| --surface | #fbfdfd | #17252b | Main surface |
| --surface-subtle | #eaf1f3 | #1c2d34 | Grouped secondary surface |
| --text | #152c35 | #edf5f7 | Primary text |
| --muted | #536971 | #adc1c9 | Supporting text |
| --line | #d4e0e5 | #354b55 | Dividers and input edges |
| --accent | #0b7285 | #75d6df | Primary action/selection |
| --accent-hover | #085d6d | #96e2e8 | Primary action hover |
| --on-accent | #f7fdfd | #0d282e | Text on accent |
| --accent-soft | #dceff1 | #183b43 | Selected navigation/subtle accent |
| --danger | #b42318 | #ffb4ab | Destructive action/failure only |
| --success | #28754d | #91d5ad | Actual completed/connected state only |
| --warning | #8c590b | #f4cc89 | Actual pending attention only |

All color declarations use these roles (and derived alpha shadows). Do not use
purple, pure black/white backgrounds, gradients behind text, or a second
decorative accent. A service's Running state is not remote-request readiness.
Forced-colors uses system colors and real borders/focus outlines. Root checks
contrast after rendering; values above are design intent, not a passed audit.

## Typography

- Text stack: `"Segoe UI Variable", "Segoe UI", "Noto Sans KR", "Malgun Gothic", sans-serif`.
- Android may prefer `Roboto, "Noto Sans KR", sans-serif`; preserve CJK fallback.
- Monospace details: `"Cascadia Code", Consolas, "Noto Sans Mono CJK KR", "Malgun Gothic", monospace`.
- Base 1rem/1.6; desktop body may use 0.9375rem. Headings 1.75rem and 1.25rem,
  weights 650/600; body 400/500. Small supporting text no smaller than 0.8125rem.
- No fixed-height text clipping. Balance short headings, pretty-wrap short
  descriptions, use tabular figures for time, and wrap long paths/commands.
- Preserve system text scaling/zoom; do not force a minimum browser font size.

## Spacing and geometry

4px base: --space-1 0.25rem, --space-2 0.5rem, --space-3 0.75rem,
--space-4 1rem, --space-5 1.25rem, --space-6 1.5rem, --space-8 2rem,
--space-10 2.5rem, --space-12 3rem.

- Desktop sidebar 13.5rem; content padding 2rem (1rem at narrow bounds).
- Desktop native window initial 980x740, minimum 760x580. Browser QA additionally
  stresses 390/768/1280 widths; those are not native-platform proof.
- Phone content max 42rem, margin auto; horizontal padding 1.25rem.
- --radius-control 0.5rem; --radius-card 1rem; phone primary controls 1rem.
  Closely nested radii use outer = inner + intervening padding.
- Native buttons are not redrawn in HTML. HTML buttons have at least 44px desktop
  and 48px phone hit areas. Weekday chip targets do not overlap.
- Main owns page scrolling. Command details may have a separate bounded scroll
  region with a visible purpose and keyboard access. Bottom navigation must not
  cover text, input or actions; safe-area/keyboard handling belongs to the shell.

## Components and states

- Desktop: native caption, compact task navigation, PC state, connected phones,
  activity. One setup/manage action where the native owner permits it.
- Phone: request-first layout, connected PCs, notification schedule, activity.
  Secure-lock-missing is distinct from readiness unknown/error.
- Request: PC + program + executable; optional command disclosure labelled
  `더 보기`. Approval and denial labels are `승인` / `거부`. No editable Windows
  credentials in WebView; eventual credential entry is native-owned.
- Forms: visible labels, field-level validation, save/cancel, dirty-state
  preservation on failure. Settings become saved only after Rust confirms.
- Destructive commands require consequence-specific confirmation. Escape/close
  restores focus; repeated submission is disabled while pending.
- Unavailable future operations are not enabled buttons. No fake QR, paired
  device, completed approval or live latency number in the production app.
- Every icon has one purpose; use local SVG shapes, not emoji or icon-only labels
  without accessible names. Decorative shapes have no focus/interaction role.

## Motion

--motion-fast 140ms, --motion-normal 200ms, --ease-standard cubic-bezier(.2,0,0,1).
Use transitions on opacity/transform/background-color/box-shadow only where
needed, never `transition: all`. Press scale .96 for app buttons. Avoid page-load
entrance choreography on an urgent request screen. Reduced motion removes the
transform/transition while preserving state, progress and focus. Animation never
commits a service decision or reports success.

## Depth

Small tonal separation and a quiet surface shadow: `0 1px 2px rgb(21 44 53 / .04),
0 4px 16px rgb(21 44 53 / .04)`. Use dividers for grouping and visible input/focus
edges. Dark mode uses tonal layers and a subtle ring rather than heavy shadows.
No glass blur, faux operating-system chrome or ornamental status badges.

## Client token bindings

`ui/src/styles.css` binds the values above to reusable tokens. Additional bounded
layout values introduced by the first client are:

| Token | Value | Role |
| --- | --- | --- |
| --sidebar-width | 13.5rem | Desktop navigation rail, as specified above |
| --content-max | 66rem | Maximum desktop content measure at wide browser QA bounds |
| --phone-content-max | 42rem | Phone content and bottom-navigation measure |
| --target-desktop | 44px | Minimum desktop action target |
| --target-phone | 48px | Minimum phone action/input target |
| --text-small | 0.8125rem | Supporting text and compact output |
| --text-caption | 0.875rem | Notice/request secondary text |
| --text-body | 0.9375rem | Desktop body and small section labels |
| --text-normal | 1rem | Phone body and form controls |
| --text-brand | 1.125rem | Compact application identity |
| --text-section | 1.25rem | Section headings |
| --text-title | 1.75rem | Page and request program headings |
| --shadow-surface | Depth value above; dark `0 0 0 1px var(--line)` | Quiet grouped-surface depth |
| --overlay-scrim | `rgb(21 44 53 / .4)` | Modal backdrop, derived from primary ink |

The 42rem rail-to-top-navigation change point preserves content at browser
stress/zoom bounds; 52rem reduces desktop content padding. At 24rem phone padding
shrinks one spacing step. At 20rem time fields and action groups stack and phone
navigation becomes two columns. These are app-owned adaptation intentions,
unverified until root renders and exercises them; they do not change native
minimum window bounds. Weekday chips wrap instead of shrinking below 48px.
