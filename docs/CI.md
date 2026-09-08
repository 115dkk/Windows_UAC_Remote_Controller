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
- Project license enforcement and a raw dependency license metadata inventory
  under `target/quality/license-inventory.json`. This is not legal clearance or
  a substitute for the release's corresponding-source and notice bundle.

`node tools/quality.mjs --extended` additionally runs Android Rust **core** Clippy,
excluding exactly `controller-app`. Install the target first
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

## Action/runtime selection

Checked against upstream releases on 2026-09-08:

| Action | Release | Pinned commit | Runtime |
| --- | --- | --- | --- |
| actions/checkout | [7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1) | `3d3c42e5aac5ba805825da76410c181273ba90b1` | Node 24 |
| actions/setup-node | [7.0.0](https://github.com/actions/setup-node/releases/tag/v7.0.0) | `820762786026740c76f36085b0efc47a31fe5020` | Node 24 |

Both PR and main jobs have read-only repository permission. Checkout does not
persist credentials. Dependency/build caches are not shared with privileged
release jobs. No `pull_request_target` or ignored failure is used.

## Incomplete release work

The current tree contains the native presentation shell and service foundations,
not a functioning installable remote UAC controller.
No release is published from these libraries as though it were the product.
The main-push installer build/automatic release workflow remains required and
will be added with the Windows/Android applications, source bundle and signing
contract. No remote Actions run or repository branch-protection change has been
performed merely by writing this workflow.

## Current local environment limitations

The Windows/Android Rust shell compiled on 2026-09-08. APK packaging stopped at
Tauri's symbolic-link creation because the local Windows account lacks that
permission. No security policy or developer-mode setting was changed, and no
copy/alternate packaging path was used to evade that denial. A separate Kotlin
compilation/unit-test attempt stopped earlier in Gradle's immutable transform
cache rename, including with a new task-private Gradle cache. It did not run the
eight authored JVM tests. Native and browser screen-control permissions were
also denied; neither rendered surface has a successful capture yet.

Rust 1.97 reports the Korean MSVC import-library progress line as a
`linker_messages` warning when linking a cdylib. This matches the documented
[upstream regression](https://github.com/rust-lang/rust/issues/159133).
Clippy's warning gate remains unchanged, and the warning has not been hidden
with a lint allow or output filter. A warning-free distributable build remains
an outstanding release check.
