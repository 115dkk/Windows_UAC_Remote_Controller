# Android diagnostic Save slice

## Implemented scope

- Added `save_android_diagnostics` with no renderer arguments. Serialized successful outcomes are exactly `"saved"` and `"cancelled"`; other outcomes reject with `diagnostics_save_unavailable`.
- Existing `export_android_diagnostics` still opens the Android share chooser. Save separately uses native `ACTION_CREATE_DOCUMENT`, `CATEGORY_OPENABLE`, `text/plain`, and a fixed diagnostic filename. Users select device storage / Downloads or an available document provider.
- The original physical Activity/WebView adapter owns the picker and pending reply. Unique registry keys isolate stale restored results; completion or adapter retirement unregisters the callback. Cancel returns `cancelled`; Activity retirement fails the old request instead of transferring it to a replacement WebView.
- Save uses the existing process-wide single-worker export lease and bounded closed-token snapshot renderer. No file IO, logcat wait, or diagnostic collection runs on the main thread. No renderer-provided URI/path, wide storage permission, persistent URI permission, or service-running requirement was added.
- Successful `saved` means the selected provider's output stream was written, flushed and closed. Provider failure or writer timeout reports unavailable. The lease remains occupied until an already-started provider operation returns; a failed/timed-out provider may leave a partial or completed selected document. The application does not delete user-selected documents or misreport a timed-out operation as saved.

## Authored checks; execution belongs to ROOT / CI

- Kotlin JVM pure-state regression cases: single selection, single completion, normal cancellation, retirement before selection, timeout before late writer success.
- Rust closed-result deserialization/serialization and source-contract tests for native origin, empty arguments and admission.
- Node source contracts cover document-picker action, content-only result, worker IO, shared lease, no chooser in Save, no wide/persistent grants, adapter retirement and separate cancellation result.
- Added `AndroidDiagnosticSaveInstrumentationTest` using a real MainActivity, Android document picker accessibility actions, Back cancellation, actual result callback, production exporter, and read-back from the selected provider URI. It validates the bounded diagnostic header/sections, leaves one small synthetic-named file on the disposable AVD, and adds no production test API. This specific test invokes the exporter through its own test-side registry callback, so it proves native picker/provider behavior rather than the JavaScript bridge or product adapter lifecycle wiring.
- Wired the class into the already-guarded `tools/android-language-ci.mjs` lifecycle-AVD runner. Failure propagates, and raw instrumentation output is retained at `target/android-lifecycle-ci/diagnostic-save-tests.txt` with the existing CI artifacts.
- No builds, tests, lint, format commands or device validation were run by this child. Native CI results, physical-phone behavior and recreation validation remain ROOT's responsibility; authored tests alone are not passing evidence.

## Service log interpretation

The initially pasted excerpt ends partway through a timestamp. Its complete records show application creation, package-replaced reception on an unlocked device, and activation ON. They contain no service death or failure cause. ROOT later supplied the full-log summary: service creation/promotion/start, owner READY in 125 ms, then repeated attached/promoted START_COMMAND and generation accepted, with the latest start 1.5 seconds before export. That summary supports service responsiveness during that interval, not a causal service-death fix. No service lifecycle behavior was changed in this slice.
