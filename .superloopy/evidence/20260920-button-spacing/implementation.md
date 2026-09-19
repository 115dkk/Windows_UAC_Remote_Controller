# QR / USB action spacing

Scope: mobile connected-PC action row and PC pairing card, existing React/plain
CSS in Windows/Android embedded clients. User photo is the observed mobile defect.
Baseline208fc9e; existing untracked attachments preserved.

## Findings and implementation

| Severity | Location | Before | After | Reason |
| --- | --- | --- | --- | --- |
| Medium | ui/src/styles.css collection-actions | Flex row without gap or wrapping | Existing --space-3 (0.75rem) on both axes; flex-wrap | Separate hit areas and preserve spacing on narrow/enlarged views |
| Checked | PC pairing-entry buttons | Full-width stacked buttons, --space-4 top margin | Retained; real geometry regression added | No source evidence of the mobile zero-gap issue on this surface |

Same shared row is used by desktop single-button save/history actions; a gap adds
no padding to a one-button row. No new token/framework, event handler, capability,
translation, Rust/service/native code or auth/pairing semantics changed.

## Review coverage

- Surfaces/hit areas: two-button separation and existing44/48px minimums.
- Typography: existing fonts unchanged;200% text layout is in CI coverage.
- Color/icons/motion/performance: unchanged, no new claim or animation.
- Considered/rejected: per-button margins (duplicate layout knowledge), forced
  full-width mobile buttons (unnecessary layout change). Existing gap token fits.

## Required ROOT CI evidence

New synthetic phone device fixture matches the user's screen without copying the
real PC identity. Gallery checks measured gaps, widths, hit heights, and Tab order
on phone390/320/200% and PC980/390/200%, plus disabled PC setup. Screenshots and
geometry JSON are retained by the actual CI reporter. ROOT must download/view
actual images. Browser proof is for shared client layout, not native USB/UAC.

Status: implementation complete; static security/architecture review and CI pending.
Skills: make-interfaces-feel-better (existing tokens/hit areas), Superloopy evidence.

ROOT accepted the fresh architecture recommendation: no additional refactor.
Security source review passed; fresh general usage observation17% used preceded
the final architecture review. PC gallery minimum tightened to existing1rem.
Existing native CI now reads actual Android WebView accessibility bounds on the
unpaired PC-list page and actual Windows WebView2 button bounds, retaining PNGs.
These additions navigate only; they do not click pairing actions or inject state.
ROOT will inspect those native captures alongside the responsive client gallery.

CI1787db4:145/146 browser cases passed. The new PC200%-text case exposed horizontal
overflow in the same page (main scrollWidth679 vs clientWidth517). QR/USB bounds
and gap assertions passed before the full-page overflow check. The adjacent
external-relay text input lacked any intrinsic-width cap; constrain only that
input to its form content width and add explicit field containment measurements.
No input value, validation, submission, color or font changes.

CI0f7fb0d:145/146 browser cases passed; the new input containment and page overflow
checks passed. The pairing200% case then reached a legacy desktop-wide branch
that searched for status-page activation buttons. Scope only those action checks
to desktop-running; retain shared200% navigation checks for both desktop pages.
