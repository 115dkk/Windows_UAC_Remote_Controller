# CI findings

-2cc1c00 UI checks:require-await on new Diagnostics.test.tsx callback. Fixed by
 awaiting exact held promise in7f6f6e1, not suppressing lint.
-7f6f6e1 quality:public-diagnostics-contract still searched release template for
 the deferred Explorer acceptance sentence moved by user request. Updated to
 require immutable verification link plus the same sentence in separate document.
-Experimental Windows run35581683195 attempt1 at816facc failed before latency
 measurement:comparison-signed-acceptance, phone fixed reason close_failed.
 Real management checks passed; software enrollment did not complete. No latency
 value was produced. Downloaded actual failed proof under latency-attempt-1.
 Retried exact unchanged run once; native validation/gates remain unchanged.

-6119e19 native lifecycle run35584125586 passed preceding lifecycle/scanner/
 locale checks and real picker Back cancellation, then test automation selected
 the toolbar Downloads text instead of the actual drawer root. Actual bounded
 DocumentsUI node49 is android:id/title, while node32 toolbar text has no ID or
 clickable ancestor. ROOT inspected actual failure PNG and node summary, scoped
 selector to that observed title ID and waits for visible roots_list to disappear.
 Product save implementation unchanged. Added small-artifact capture paths so
 future native diagnosis need not download the91MB APK evidence bundle.
