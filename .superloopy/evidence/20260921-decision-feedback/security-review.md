# Independent static security/correctness review

- Date: 2026-09-21
- Reviewer: security_review child agent (read-only product review; evidence-only write)
- Baseline: `edfeeb204694ea4ffc1fed411247e9bbcc711729`
- Scope: current working-tree delta for Android diagnostic file save, bridge and UI outcomes, release notes/history, and CI-only denial latency observation.
- Validation: static source inspection only. No build, tests, lint, formatter, executable/device QA, commit or push was run by this reviewer.

## Result

No concrete high- or medium-severity security/correctness finding was identified in the reviewed delta. No product-source fix was made. Approval is conditional on ROOT's exact-commit CI, required native artifacts and visual review; this report is not execution evidence.

## Native storage and authority

- `ui/src/bridge.ts` supplies no path, URI, text, recipient or capability. `src-tauri/src/commands.rs::save_android_diagnostics` requires the existing whole-body `EmptyArguments` check and native `CommandOrigin`, then takes the existing command admission lease.
- `src-tauri/src/mobile.rs` invokes `run_mobile_plugin_from_origin`; `DeviceStatePlugin.dispatch` retains the actual originating physical WebView. `DeviceStateActivityCommands.saveAndroidDiagnostics` rechecks arguments and foreground state. The picker result is tied to the original adapter and exact operation identity, not renderer arguments or a later current Activity.
- Native `ACTION_CREATE_DOCUMENT` uses `CATEGORY_OPENABLE`, `text/plain` and an app-generated filename. Only a returned `content:` URI is accepted. No broad storage permission, persistent URI grant, JS write path or authorization authority is added.
- Activity/WebView retirement terminates the original operation and unregisters its result launcher. A unique registry key prevents a restored old result from being consumed by a new operation. Ordinary picker-induced pause/stop does not retire the physical binding, allowing the result to return normally.
- The existing bounded closed-token renderer is shared by file save and sharing. No new log payload or private-key/request-body export is introduced.

## Completion, lifetime and resource accounting

- `SAVED` follows successful write, flush and `use` scope exit; a close exception is caught as unavailable. Picker cancellation has its own closed `CANCELLED` result. Vendored Tauri `Invoke.resolveObject` serializes string values directly, matching the Rust lowercase enum and TypeScript union.
- The terminal gate permits a single reply. Retirement or write timeout prevents later success. The original completion closure is not redirected to a newer renderer.
- Provider write runs on the existing one-thread bounded executor. The process-global lease is retained until started IO returns, including after the 15-second response timeout; a stuck provider cannot accumulate writer threads or exports. The retained obligation can leave diagnostics unavailable until IO/process recovery, which is a bounded availability tradeoff, not a success claim.
- The user-controlled picker waiting period is intentionally not a provider-write timeout. While pending, existing command admission and UI busy state serialize operations. UI completion preserves current withdrawn request state and distinguishes saved/cancelled/failure without mutating activity history.

## Tests and evidence scope

- JVM tests exercise the pure selection/terminal gate, not Android lifecycle or provider IO.
- The new instrumentation drives actual Android DocumentsUI Back cancellation and a real selected provider, invokes the production exporter, reopens the result and checks bounded diagnostic bytes. It does not traverse the JavaScript/Rust bridge, and its comments/CI output explicitly preserve that limit.
- Static inspection found no definite Kotlin type/SDK mismatch. Actual DocumentsUI widget identifiers and focus/lifecycle behavior remain CI observations, not conclusions from this review.
- Synthetic UI gallery coverage is labelled client/synthetic and separate from native storage proof. ROOT must inspect the generated gallery and native instrumentation output.
- Close failure, hung provider and physical Activity recreation are covered by source invariants/pure gate tests, not claimed as new end-to-end native tests. These are useful future native regression cases, not grounds to substitute mocks for devices.

## Release history and retained gates

- Published releases are fetched with pagination; drafts and unpublished tags do not advance the boundary. Only version-shaped tags are considered, and the selected base is the nearest ancestor of the exact checked-out release commit.
- Full Git history, exact HEAD/SHA/current-tag binding and merge-base status are checked. A missing published tag fails rather than silently broadening the range. The global publication concurrency group already serializes different release tags.
- Notes show at most eight non-release-metadata subjects from the new range and link to the full immutable comparison. Commit subjects are HTML/Markdown escaped; templates are interpolated once, so inserted subjects cannot inject template values.
- Verification detail moves to an immutable commit-linked document plus version-bound release asset. Historical observations remain distinguished from new-install acceptance. Required release gates are not removed or weakened; new note tests join the existing quality run.

## Latency observation

- The new monotonic sample starts after the intentional renewal hold. It covers software-phone signing/queue through authenticated same-request Windows resolution verification, not Android authentication, button-to-frame, mobile-network or approved execution latency.
- Existing matching request/digest/outcome checks and Windows `ERROR_CANCELLED`/non-execution proof remain in place. Measurement does not create a new approval path or relax any authentication, UAC or connection gate.
- The research document correctly labels this as one software-phone denial sample and leaves the proposed receipt UI unimplemented. Publication/reporting must retain these boundaries.

## Supplemental final-architecture review — 63fcef4

Static re-review of `refactor(android): centralize diagnostic document save lifecycle` found no concrete high- or medium-severity regression. Product files were read only; no validation commands were executed.

- `AndroidDiagnosticExporter.SaveOperation` now owns picker registration, result handling and unregister, together with the writer and terminal gate. `DeviceStateActivityCommands` retains only its operation slot, original physical `matches(webView)` predicate, retirement and closed reply mapping.
- `beginSave` posts picker launch to the main queue after creating the operation. This lets the caller install its slot before launch failure or a picker result can complete it. If the adapter retires before that queued launch, the terminal gate prevents opening the picker and retirement releases the unused lease.
- Foreground and current-origin predicates are both checked before launch; results require current physical identity but not foreground focus, because DocumentsUI normally covers the host. Unique registration, retirement, worker lease, provider write/flush/close and exactly-once completion invariants remain intact.
- Instrumentation now invokes the same production `beginSave` orchestration instead of registering its own picker. It selects the observed Downloads root, writes a fresh test-generated UUID filename through the system UI, then reads that exact file with bounded `head -c 393217`. The filename is restricted to an anchored ASCII prefix/UUID/extension grammar before shell interpolation; the command adds no deletion, arbitrary path, product getter or product storage permission.
- The readback changed from `ContentResolver.openInputStream(uri)` to exact-path shell readback in the disposable emulator. Its evidence is therefore real production picker/write plus resulting file bytes, not a new production read API or proof that arbitrary document providers support re-opening. The saved document is retained, and a missing/wrong file fails its header/size checks.
- Source contracts were updated to require exporter-owned registration and forbid duplicate test/adapter registration. Existing origin, no-argument, URI, closed-outcome and bounds checks remain. The deferred Windows shell-opening assertion now follows the verification document linked by the compact release template; no native gate was removed.

ROOT must still verify the exact committed CI run, including DocumentsUI root selection on the guarded API36 image. JavaScript-bridge end-to-end and physical-phone claims remain outside this instrumentation's scope.
