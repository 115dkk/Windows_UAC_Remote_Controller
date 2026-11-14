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

Found by building this workspace with it, and not in the announcement:

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

The new build-directory layout needed nothing: no script here reaches inside
`target` for intermediate files.

## Verification

On an arm64 Ubuntu 24.04 host with the pinned 1.100.0:

- `cargo fmt --all -- --check`.
- Clippy with `-D warnings`, all targets and features, for the host; for
  `aarch64-linux-android` with the workspace's Android exclusions; and for
  `x86_64-pc-windows-gnu` without the Tauri shell, whose build script needs a
  Windows resource compiler. That last run is what type-checks the
  Windows-only code off Windows; it is not the MSVC target CI builds.
- The workspace tests and doc tests for the host.

Not run there: anything that executes a Windows or Android binary, the Tauri
shell for Windows, and the rust-analyzer canaries. CI runs those.
