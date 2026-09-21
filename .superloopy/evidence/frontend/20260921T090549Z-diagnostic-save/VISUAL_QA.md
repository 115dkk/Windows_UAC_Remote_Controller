# Diagnostic save client review

ROOT downloaded actual CI35582312585 Linux gallery artifact for PR head7f6f6e1,
merge checkout a21385606037d1b7c2f4248ff4fdf428e739b115. Ubuntu24.04,
pinned Chromium, synthetic QA adapter. Production client build/TypeScript/lint/
UI tests precede the separate QA build. This is client proof, not Android storage.

Direct visual inspection:320x740 light and dark diagnostics-save-ready;
390x1000 with200%root text diagnostics-save-ready. Save is first, Share second,
Clear separate danger-quiet. No overlapping controls or clipped save label;
200%label wraps and focused save remains in viewport.48px minimum touch targets
and keyboard focus checked by gallery. Existing scroll owner and tokens retained.
The200%capture is scrolled to the save action; offscreen history is not clipping.

Files under ci-7f6f6e1-linux/results/gallery-client-diagnostics-export*/ include
ready/acknowledged/pending states. Screenshot evidence is held locally, not a
claim that a real document was saved by that synthetic adapter.

Review mode: scoped full, existing-system diagnostic actions only. Typography,
surfaces, focus/target size and light/dark inspected; animations unchanged;
Qt/icons/performance redesign not applicable. No actionable polish finding in
this delta. Native picker, provider IO, physical phone and TalkBack are separate
evidence. Native CI pending. Later source revisions require attribution against
the final commit before release completion.

Rejected alternatives: explaining Downloads alone retains forced share;
full-screen custom save UI duplicates Android's storage picker; icon-only save
would obscure the user's requested distinction. No new design-system dependency.
