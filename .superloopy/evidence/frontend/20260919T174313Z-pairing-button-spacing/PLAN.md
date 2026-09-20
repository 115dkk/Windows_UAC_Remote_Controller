# Narrow spacing correction

Current-surface delta, not a redesign. User-supplied Android screenshot establishes
the zero-gap defect; its PC identity is not copied into test data. Existing DESIGN
tokens own the fix. Code inspection identifies .collection-actions as the layout
owner. PC pairing buttons already have independent stacked spacing.

Targets: installed Windows11 x64 Tauri/WebView2 client and Android API30+ Tauri
WebView client; shared React DOM/CSS owns the changed pixels. Native chrome,
permissions, bridge, protocol, authentication and persistence are unchanged.
Existing real-shell/package/lifecycle CI remains the platform regression floor.

Acceptance: >=0.75rem clear separation between QR and USB hit rectangles in
either axis; no horizontal overflow;44px PC/48px phone minimum height; same DOM
and keyboard order. Phone390/320/200% text and PC980/390/200% text, including
disabled setup, are exercised by production-compiled synthetic client galleries.
Phone photo is current-state evidence, not pixel-perfect reference authority.

Implement gap and wrapping via existing shared CSS rule; retain labels, handlers,
state truth, colors, fonts and native ownership. Adjacent single-button save and
history rows retain their geometry. No generated visual/media/SEO/motion claim.

Frontend references: UX, Web, layout, desktop, mobile, hybrid, image-first.
CI owns all builds/tests/rendering; ROOT downloads and inspects real artifacts.
Browser captures prove client geometry only, not physical devices or native USB.
Final VISUAL_QA.md and target-owner evidence rows will reference actual captures.

No aggregate Superloopy completion claim: G006 covers a broader historic product
journey. This receipt addresses only the requested spacing correction.
