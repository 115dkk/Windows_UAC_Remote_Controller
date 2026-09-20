# Quality gates

The root agent runs local validation. Child agents only author code/tests and
perform static review. CI repeats the same checks on clean hosted machines.

Run `node tools/quality.mjs` from the repository. It fails on the first nonzero
command, process launch failure, timeout or signal. It runs:

- Strict TypeScript, ESLint with zero warnings, Vitest and the production Vite
  build, using the running Node executable and installed JavaScript entry points.
  This creates `dist/index.html` before Tauri's embedded-assets compilation.
- Rustfmt check.
- Clippy on every workspace target/feature, with `-D warnings`.
- Cargo tests and separate documentation tests using the lockfile.
- Actual Rust Analyzer diagnostics: all errors/warnings and all non-configuration
  hints fail. Only the exact `inactive-code` cfg-shading hint is informational;
  native/Android target checks and host tests cover the different configurations.
- Tests of the analyzer output/exit gate.
- Real analyzer clean/error/warning canaries on both host operating systems.

Rust license policy is checked separately by the `Cargo Deny licenses` CI job:
`cargo deny --locked --all-features --workspace check licenses`. `deny.toml`
includes workspace, build and development dependencies. Unaccepted/unknown
licensing fails the job. The upstream Docker action is commit-pinned and uses
cargo-deny0.20.2, with no Node20 action runtime.

`node tools/quality.mjs --extended` additionally runs Android Rust **core** Clippy,
excluding `controller-app` and the host-only `controller-uniffi-bindgen` tool.
The host jobs check the generator. Install the target first
with `rustup target add aarch64-linux-android`. CI runs these same checks across
its separate host and Android-core jobs. This exclusion does not establish an
Android app build. The full shell needs SDK, NDK, Gradle, Kotlin and device gates.

Install the frontend with `npm ci`, using the Node version in `.node-version`.
Linux host jobs install the official Tauri Debian/Ubuntu development packages
before testing the full workspace. The package lock pins compatible Vitest 4.1.11
and TypeScript 6.0.3; newer incompatible test/type packages are not accepted by
weakening `skipLibCheck` or the typed lint rules.

`rust-analyzer diagnostics` does not itself make warnings a nonzero exit. The
adapter in `tools/rust-analyzer.mjs` requires a completed scan, rejects any emitted
actionable diagnostic or loading warning, and checks the process outcome. The
CLI calls LSP Hints `WeakWarning`; only its exact inactive-cfg annotation is
recorded separately, not treated as a source defect. No general warning category
is suppressed. Raw diagnostics remain in `target/quality/rust-analyzer.txt`.
The LSP distinction is explicit in [Rust Analyzer's severity mapping](https://github.com/rust-lang/rust-analyzer/blob/master/crates/rust-analyzer/src/lsp/to_proto.rs).
Its output format
is tied to `rust-toolchain.toml`; do not update that version without exercising
`node tools/verify-analyzer-gate.mjs`. That command creates isolated disposable
clean/error/warning crates and runs the real analyzer against them. Failure to
start a process does not count as successful negative-test evidence.

Source contract: [Rust Analyzer diagnostics implementation](https://github.com/rust-lang/rust-analyzer/blob/master/crates/rust-analyzer/src/cli/diagnostics.rs).

The workflow runs Windows and Linux host tests plus an Android Rust cross-target
check. A cross-target check is not Android installation, notification, biometric
or background-execution testing. Those require the actual native application.
The analyzer currently scans the pinned toolchain's native/default-feature
workspace configuration; Clippy additionally covers all features and the Android
target. Revisit analyzer coverage when platform-specific crates/features exist.

The pinned CLI queries rustc cfg with `-O` but does not supply the LSP's
`debug_assertions` override. The gate explicitly appends rustc's
`-Cdebug-assertions=yes` in its child environment to match `[profile.dev]`.
Existing flags are preserved, including Cargo's encoded-flags precedence; the
parent environment is not modified. This supplies the actual configuration,
not a diagnostic exclusion. The Tauri ACL debug fields otherwise disagreed with
the dev-compiled code generator. See the [pinned cfg query](https://github.com/rust-lang/rust/blob/1.97.0/src/tools/rust-analyzer/crates/project-model/src/toolchain_info/rustc_cfg.rs).

The local MIT-option `tauri-codegen` patch supplies the actual icon byte-array
length to its generated `include_bytes!` expression. The analyzer otherwise
leaves that array's length unknown when the expected type is a slice. Real
cached bytes, dimensions, CSP, capabilities and runtime code are unchanged;
rustc checks the exact length. See `vendor/tauri-codegen/LOCAL_PATCH.md` for
provenance and removal criteria. Generated context is still analyzed.

The local Wry 0.55.1 override updates two Android Kotlin templates without ignoring
app warnings: unused deprecated WebSQL enablement is removed and the disabled
Back callback uses the dispatcher. Three Rust typing/cfg expressions are made
explicit for the pinned analyzer after CI exposed dependency-source diagnostics.
There is no vendor-directory analyzer exclusion. See
`vendor/wry/LOCAL_PATCH.md`; fresh target CI is required after each change.

## Native Android package and client gallery

`android-package.yml` builds the real Tauri arm64 debug APK on Ubuntu with Java 17,
Kotlin 2.2.21, AGP 8.11.0, Gradle 8.14.3, API 36 and NDK 28.2.13676358. It then executes
the real Gradle JVM tests and passively inspects the packaged Rust components and
JNA library for required ABI, bounded ELF ranges and 16KiB load-segment alignment.
The inspector emits hashes and metadata, never loads native code. It does not
prove release signing, device startup, 16KiB device compatibility or authentication.

The first successful actual package build was [run 34288751092](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34288751092)
at source `aebb662ea05c3368e42394c43ac68602b70a96c9`: 44 JVM tests passed, none skipped,
and the APK contains exactly the three expected arm64 libraries. ROOT downloaded
the reports/APK and matched its SHA256. This historical package success does not
claim that later revisions or the separate full-quality job passed. Upstream
Tauri's separately compiled Android library still emits warnings; app warnings
remain errors.

`ui-gallery.yml` builds a separate synthetic-state entry using the same React
components, then captures Chromium on Windows and Linux. That entry cannot build
into the production output. These are client screenshots, not Android screenshots
or native Windows/UAC proof. The user authorized CI captures after local screen
permission was unavailable. Reviewed representative images are in
[issue 1](https://github.com/115dkk/Windows_UAC_Remote_Controller/issues/1).

## Stateful protocol security

The separate `Protocol security (Tamarin)` job runs official Tamarin 1.12.0 with
supported Maude 3.5.1. `tools/install-tamarin.mjs` verifies the pinned archive
SHA-256 values before extraction and checks the actual executable versions.
No local Windows prover installation is needed for this CI job.

`security/tamarin/manifest.json` requires thirteen baseline properties and three
mechanism-removal controls. Honest traces must exist; the secure models must
verify their safety properties; pin/signature/replay-guard removal must produce
actual counterexamples to the named properties. Missing, false, unfinished,
warning-bearing, timed-out or wrong-input summaries fail. A zero process exit
alone is not a proof verdict. Immutable model snapshots, source-binding hashes,
exact arguments, full bounded logs and partial results are retained as artifacts.

Each baseline lemma runs separately under a bounded process owner; witness
search uses BFS and safety search uses DFS. These are search strategies, not
trace/depth bounds or permission to skip obligations. The runner's own tests
exercise timeout/cancellation, output limits and rejection of stale or mixed
evidence. The Linux job also executes its POSIX descendant-cleanup tests.

After a completed failed normal run, a separate diagnostic helper may investigate
one failed request lemma with proof depth12, at most60seconds and4MiB combined
output. It retains a labelled proof-method skeleton/log, not an accepted proof
or a dump of all unsolved constraints. Its metadata always says
`eligibleAsProof:false`, even if the diagnostic unexpectedly finishes. Normal
proof artifacts are uploaded first; diagnostic artifacts use a separate name
and directory. The normal failed step still fails the job; there is no
`continue-on-error`, replacement verdict, automatic deeper retry or ingestion of
the diagnostic output as a production theory.

The `ce69210` depth8 skeleton stopped after the key-source premises. A depth16
diagnostic on `b5b3b19` hit the fixed60second limit without a completed skeleton.
The next isolated observation uses their midpoint12; the model and search ranking
remain unchanged. This does not guarantee completion within60seconds, and
proof-step counts are not the same as proof depth. Each CI run still performs
only one diagnostic, never an automatic retry/search-depth loop.

The [model contract](../security/tamarin/README.md) documents the trusted
enrollment/authentication premises, explicit mutable registry and one-shot
request lifecycle, code mapping and cryptographic abstractions. These models do
not prove native OS isolation, hardware-key behavior, complete implementation
refinement or real network latency. Their existence in CI does not mean all
required proofs have passed; current results are recorded in [PROGRESS.md](PROGRESS.md).

The Android package job additionally decodes each actual merged APK manifest
and requires the default-enabled private boot receiver, foreground-service
declarations and unbounded required permissions. This supplements Kotlin/Rust
lifecycle tests; it does not simulate a physical reboot or first-unlock event.

## Action/runtime selection

Checked against upstream releases on 2026-09-08:

| Action | Release | Pinned commit | Runtime |
| --- | --- | --- | --- |
| actions/checkout | [7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1) | `3d3c42e5aac5ba805825da76410c181273ba90b1` | Node 24 |
| actions/setup-node | [7.0.0](https://github.com/actions/setup-node/releases/tag/v7.0.0) | `820762786026740c76f36085b0efc47a31fe5020` | Node 24 |
| actions/setup-java | [6.0.0](https://github.com/actions/setup-java/releases/tag/v6.0.0) | `dd06d9cba3e5552c54d9f8ea23572deb30010f7c` | Node 24 |
| actions/upload-artifact | [7.0.1](https://github.com/actions/upload-artifact/releases/tag/v7.0.1) | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | Node 24 |

Both PR and main jobs have read-only repository permission. Checkout does not
persist credentials. Dependency/build caches are not shared with privileged
release jobs. No `pull_request_target` or ignored failure is used.

## Incomplete release work

The user's September11 instruction replaces bespoke license checks/collection
with Cargo Deny. Additional original-material searches and collection are stopped.
Previous scripts, imported originals and generated evidence remain preserved as
reference material, but are not default CI gates. Cargo Deny is a policy check,
not a notice archive or a corresponding-source publisher. See
[Rust license checks](RUST_NOTICE_MATERIALS.md) for the current command and scope.

The current tree contains the native presentation shell and service foundations,
not a functioning installable remote UAC controller.
No release is published from these libraries as though it were the product.
The main-push installer build/automatic release workflow remains required and
will be added with the Windows/Android applications, source bundle and signing
contract. Feature-branch CI has run; actual PR/main events and release execution
remain separate requirements. Repository branch-protection settings have not
been changed by writing these workflows.

## Current local environment limitations

The Windows/Android Rust shell compiled on 2026-09-08. APK packaging stopped at
Tauri's symbolic-link creation because the local Windows account lacks that
permission. No security policy or developer-mode setting was changed, and no
copy/alternate packaging path was used to evade that denial. A separate Kotlin
compilation/unit-test attempt stopped earlier in Gradle's immutable transform
cache rename, including with a new task-private Gradle cache. It did not run the
authored JVM tests locally. Native and browser screen-control permissions were
also denied. Subsequent user-authorized Linux CI successfully built the APK and
ran 44 JVM tests, while Windows/Linux CI produced reviewed client galleries. This
does not change the local permissions or establish installed-app/device behavior.

Rust 1.97 reports the Korean MSVC import-library progress line as a
`linker_messages` warning when linking a cdylib. This matches the documented
[upstream regression](https://github.com/rust-lang/rust/issues/159133).
Clippy's warning gate remains unchanged, and the warning has not been hidden
with a lint allow or output filter. A warning-free distributable build remains
an outstanding release check.
