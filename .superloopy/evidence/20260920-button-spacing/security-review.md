# Button-spacing static security review

Date: 2026-09-20. Baseline: `208fc9e`. Reviewer: independent security_review.
Verdict: **PASS for this bounded static security gate. No security finding.**

Reviewed `implementation.md` and the complete 12-file working-tree diff. The only
product behavior change is `ui/src/styles.css:278`: normal-flow flex wrapping and
the existing positive `--space-3` gap. Other changes are synthetic fixtures/gallery
coverage, documentation and alpha.38 version metadata; dependency resolutions and
checksums are unchanged.

- No handlers, disabled-state checks, native commands, capabilities,
  authentication, signing, pairing authority or OS protections changed.
- QR/USB remain separate native HTML buttons in the same DOM/focus order with
  their original callbacks (`ui/src/CollectionPanels.tsx:112`). Positive row/column
  gap and wrapping separate their layout boxes; no overlay, negative margin,
  expanded hit pseudo-element, position or pointer-event changes were introduced.
  Existing minimum targets and PC full-width stacked spacing remain unchanged
  (`ui/src/styles.css:168,184`). Actual measured non-overlap is ROOT's CI check,
  not a rendered result claimed by this static review.
- The added phone fixture contains an explicitly synthetic PC identity and is
  confined to `qa-fixtures.ts`. The unchanged production entry imports the real
  bridge; Vite's product build rejects gallery-only modules and confines QA output
  to `target/ui-qa` (`ui/src/main.tsx:4`, `vite.config.ts:10`). No product/QA boundary
  was opened.
- Gallery regression source checks at least 0.75rem separation on one axis,
  viewport containment, 44/48px minimum hit height and QR-to-USB Tab order at
  normal/narrow/200%-text sizes. Artifacts are labeled CLIENT/SYNTHETIC, not native
  USB/UAC/authentication evidence (`tools/ui-gallery/gallery.spec.ts:14`).

No source edits or validators were run by this reviewer; only this evidence file
was added. ROOT must complete the requested fresh architecture review and actual
CI/gallery inspection. This review does not revisit unrelated startup diagnostics.
