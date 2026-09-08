# Wry 0.55.1 Android API and analyzer compatibility patch

Upstream: crates.io `wry` 0.55.1, the version required by tauri-runtime-wry 2.11.4.
All original licensing files and source notices are retained. This dependency is
not relicensed as original project code. The local Cargo patch changes two Kotlin
source templates and three explicit Rust typing/cfg sites; generated application
files are not patched by hand.

1. Remove the unused WebSQL `settings.databaseEnabled = true` assignment. The
   application stores policy in Rust, not WebSQL. Android deprecated this API in
   API 35 and Chromium is removing its implementation.
   [WebSettings documentation](https://developer.android.com/reference/android/webkit/WebSettings#setDatabaseEnabled(boolean))
2. With the same callback temporarily disabled, dispatch the fallback Back action
   through `onBackPressedDispatcher.onBackPressed()` instead of deprecated Activity
   `onBackPressed()`. WebView-history navigation stays unchanged. A `finally`
   restores callback enablement if the downstream handler throws.
   [Dispatcher contract](https://developer.android.com/reference/androidx/activity/OnBackPressedDispatcher#onBackPressed())

3. Explicitly type the existing GTK WebView identifier as `String` and the map
   input as `NonNull<String>`, matching the generic GLib lookup. The pinned Rust Analyzer
   reported eight inference errors at this expression in CI 34288751131 although
   the actual compiler, Clippy and tests passed. The result annotation alone left
   one pointer-inference diagnostic in CI34289874403, so the closure input is also
   explicit. A standalone ROOT reproduction showed that method-call inference
   still fails for `NonNull::as_ref`, while fully qualified `NonNull::<String>::as_ref`
   and `String::clone` pass the real analyzer. The lookup now uses those exact
   calls; no cast, additional pointer dereference or ownership change is introduced.
4. Put the two existing Windows optional tracing macro calls inside blocks with
   the same `#[cfg(feature = "tracing")]`. Their availability and execution are
   unchanged. The pinned analyzer otherwise attempts to resolve those macros in
   the disabled feature branch and reports two errors in that same CI run.

No IPC authorization, media settings, navigation policy, logging contents or
user-visible copy changes. No warning suppression or analyzer exclusion is added.
The Kotlin changes address the actual `compileUniversalDebugKotlin` warnings-as-
errors in CI 34287120337; APK 34288751092 later built with all44Kotlin tests passing.
Real Android Back/navigation behavior still requires separate device checks.
The Rust compatibility changes require fresh Windows/Linux quality results.

Original template SHA-256:

- `src/android/kotlin/RustWebView.kt`: `0c4e6e8bde658f0e2ac7563a0cc2c164d0d39af369998ddd7f5c8fd9745b4236`
- `src/android/kotlin/WryActivity.kt`: `07067830f2356858527ad8cf93d467246875c3bd15ee578af9ccacd534b83845`

Re-evaluate/remove this fork when a compatible upstream release contains both
fixes. Do not upgrade the engine's minor version merely to hide compiler output.
