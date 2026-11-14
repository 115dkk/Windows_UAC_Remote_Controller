<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0050: Rust 1.100.0, and the workarounds it retires

Status: implemented source. The gates under Verification ran on an arm64
Linux host; CI runs them again on x86-64 Linux and on Windows, where the
Windows-only tests also execute.

## Evidence

The user asked on 2026-11-14 that Rust 1.100.0 be adopted and that whatever
in it applies here be applied.

Read from the release announcement
([Announcing Rust 1.100.0](https://blog.rust-lang.org/2026/11/12/Rust-1.100.0/),
2026-11-12): the never type `!` can be named anywhere and `Infallible` is now
an alias for it; the core of the allocator API is stable; `core::mem::DropGuard`
runs a closure on every exit path and can be dismissed; `std::mem::conjure_zst`;
Cargo reports unused dependencies; Cargo's build directory is laid out by build
step; and Cargo can refuse versions published more recently than a configured
age.

Found by building this workspace with it and by running its CI, and not in the
announcement:

- `std::fs::File::try_lock` now covers Android. The implementation in
  `library/std/src/sys/fs/unix.rs` at 1.100.0 lists `target_os = "android"`
  beside Linux and calls `flock(fd, LOCK_EX | LOCK_NB)`, returning
  `TryLockError::WouldBlock` for a held lock. At 1.97.0 the same list had no
  Android and the call returned Unsupported there, which is why three crates
  made that `flock` themselves through `rustix`
  ([ADR 0004](0004-phone-checkpoint-transactions.md)). Both versions were read
  from the toolchains' own `rust-src`.
- `Atomic*::fetch_update` is deprecated, "renamed to `try_update` for
  consistency". With warnings denied that is an error.
- Clippy gained `chunks_exact_to_as_chunks` for a constant chunk size, and
  `needless_bool` now reads through a `cfg` block: a function that returns
  early on one test and then `false` on every platform but Windows is flagged
  on those platforms.
- The build-directory change removes `deps`. What one build unit produced is
  in `build/<package>/<unit hash>/out/` beside the top-level artifact, and
  the top-level artifact is a hard link to the file there. Read from the
  directory a 1.100.0 build left: `debug/relay-service` and
  `debug/build/relay-service/<hash>/out/relay_service` were one file with two
  names. The first CI run of this change (Quality 43612913222, Android package
  43612913095) is what showed it mattered here: four Android jobs stopped at
  "A required build directory is unavailable", because
  `tools/build-android-bindings.mjs` looked for the cdylib's second name in
  `deps`.
- The 1.100 rust-analyzer prints the inactive-`cfg` hint as
  `RaLint("inactive_code", WeakWarning)`; 1.97 printed
  `Ra("inactive-code", WeakWarning)`. It also reports E0599, "no method
  `inner`", for one call in the vendored Tauri that rustc compiles:
  `self.state::<PathResolver<R>>().inner()`, the only `State::inner` call in
  that file whose type argument is generic. Both failed the same CI run on
  Linux and on Windows, and both reproduce on the arm64 host with the same
  counts as Linux CI (one error, 1754 hints).
- The 1.100 rust-analyzer has no diagnostic of its own for an unused
  variable. `handlers/unused_variables.rs` is in
  `src/tools/rust-analyzer/crates/ide-diagnostics` at tag 1.97.0 and absent at
  1.100.0, and the warning canary's fixture, one unused `let`, scanned clean.
  CI never reached that canary: it runs after the scan that failed.

## Decision

The toolchain is 1.100.0 in `rust-toolchain.toml` and in the workspace
`rust-version`. The two cargo-deny steps in `quality.yml` still name 1.97.0
for the action's own cargo: the token this change was pushed with has no
`workflow` scope and may not modify workflow files. Those steps read the
lockfile and the manifests and compile nothing; raising the two lines is left
for a push that is allowed to.

Applied, because each replaces something this repository wrote for want of it:

- **File locks.** `phone-state-store`, `controller-runtime` and
  `activity-journal` call `File::try_lock` on every platform. The Android-only
  `rustix` calls and the three direct dependencies on `rustix` are removed. The
  contract is unchanged: a nonblocking exclusive lock held for the life of the
  file, contention and failure reported separately, and no unlocked fallback.
- **`DropGuard`.** Four structs declared inside a function only to run one
  statement on drop are now `DropGuard`s: the native-callback depth counter,
  the I/O thread's finished flag, and the two pairing-scan guards that cancel
  the scan unless the work completed. The last two were a hand-written
  "roll back unless dismissed", which is what `DropGuard::dismiss` is. Each
  still runs on unwind, in the same place, and the explicit cancel on the
  error path is kept beside it.
- **The never type.** The four `_unconstructible: std::convert::Infallible`
  fields that make a Windows-only owner impossible to build elsewhere are
  spelled `_unconstructible: !`.
- **`try_update`.** Ten call sites, renamed.
- **`as_chunks`.** Eighteen `chunks_exact(2)` or `chunks_exact(4)` loops over
  hex digits, UTF-16 units and SID words take `as_chunks::<N>().0`. Each element
  is then an array, so the byte-by-byte indexing and two `try_into` calls that
  could never fail are gone. Both forms drop a short remainder; none of these
  loops has one.
- **`is_link_or_reparse`.** The three copies test the symlink bit and, on
  Windows, the reparse attribute in one expression per platform.
- **Dependencies only Windows uses.** Cargo reported `qrcode` and
  `windows-dns-sd` as unused on a Linux host. They are used by the pairing
  screen and the LAN announcement, both Windows-only, and are now declared
  under `cfg(windows)`.
- **Dependency cooldown.** `.cargo/config.toml` sets
  `registry.global-min-publish-age = "3 days"`. Resolution and `cargo update`
  skip a release younger than that; a fix needed sooner is taken deliberately
  with the override named in that file. Builds use `--locked` and the committed
  lockfile, so they are unaffected.

Changed, because 1.100 moved something a gate here depends on:

- **The cdylib's second name.** `tools/build-android-bindings.mjs` accepts a
  built library with two names only when the other name is Cargo's own copy.
  It now looks for that copy in `build/android-bindings/<unit>/out/`, across
  the units of that one package, and requires exactly one of them to be the
  same file and the pair to be all the names the file has. The `deps` lookup
  is removed, not kept beside it: the toolchain is pinned, so only one layout
  can occur. No other script here reaches inside `target` for an intermediate
  file.
- **The analyzer gate.** The classifier in `tools/rust-analyzer.mjs` exempts
  one exact hint and nothing else, so it follows the new spelling, and the old
  spelling now fails as drift. The Tauri call is written by path,
  `State::inner(&...)`, which is the same function and which the analyzer
  resolves; this follows the vendored crates' existing rule that a diagnostic
  is answered in the code and never by excluding a path or a class
  (`vendor/ANDROID_LIFECYCLE_PATCHES.md`).
- **The warning canary.** `tools/verify-analyzer-gate.mjs` proves on a real
  fixture that a warning fails the gate although the analyzer exits 0. Its
  fixture is now an ignored `#[must_use]` result, which this analyzer does
  report as a warning, and the canary also requires that exit status 0, so
  the fixture cannot pass by failing some other way. The gate itself lost
  nothing it relied on: an unused variable was and is refused by Clippy with
  `-D warnings`.

Not applied:

- The allocator API and `conjure_zst`. Nothing here allocates through a custom
  allocator or conjures a zero-sized token.
- `Result<T, !>` in signatures. No function here returns a result that cannot
  fail.
- `DropGuard` for the other owners with a `Drop` implementation. They are
  named types that hold a handle, a registration or a lease, and their names
  are how the code says what is owned.
- A const initializer for the Android thread-local in `native_clock.rs`. It
  was tried again: Clippy still flags the function the Android TLS macro
  generates, as it did at 1.97, so the runtime `Default` stays.
- `[lints.cargo]`. Cargo warns about an unused dependency by default, and none
  is left.
- Removing the vendored patches that were written for the 1.97 analyzer
  (`vendor/tauri-codegen/LOCAL_PATCH.md`, `vendor/wry/LOCAL_PATCH.md` and the
  analyzer section of `vendor/ANDROID_LIFECYCLE_PATCHES.md`). Whether the
  1.100 analyzer still needs each of them was not tested.

## Verification

On an arm64 Ubuntu 24.04 host with the pinned 1.100.0:

- `cargo fmt --all -- --check`.
- Clippy with `-D warnings`, all targets and features, for the host; for
  `aarch64-linux-android` with the workspace's Android exclusions; and for
  `x86_64-pc-windows-gnu` without the Tauri shell, whose build script needs a
  Windows resource compiler. That last run is what type-checks the
  Windows-only code off Windows; it is not the MSVC target CI builds.
- The workspace tests and doc tests for the host.
- The rust-analyzer scan of the whole workspace with the gate's own flags: no
  error, no warning, 1754 inactive-`cfg` hints; and the three canaries.
- `tools/build-android-bindings.mjs` to the end, for arm64 debug: Cargo, rustc,
  the link and the UniFFI generator were real, and the built library had two
  names, the second in `build/android-bindings/<unit>/out/` among ten units of
  that package. Two things stood in for CI's: the NDK was a directory of links
  to the host's own clang and llvm-ar, and rustc's reported host was given as
  x86-64, because the script refuses an arm64 NDK host.

Not run there: anything that executes a Windows or Android binary, the Tauri
shell for Windows, and the APK builds. CI runs those.

The first CI run of this change failed in six jobs, for the two reasons under
Evidence. The first version of this record said that no script reached inside
`target` and that the analyzer canaries were left to CI; both were written
before either had been run with 1.100.
