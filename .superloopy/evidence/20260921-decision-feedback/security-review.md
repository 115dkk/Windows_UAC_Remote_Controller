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
