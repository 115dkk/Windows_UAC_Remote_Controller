# Local patch: explicit cached-icon array length

Base: tauri-codegen **2.6.3**, the crates.io package selected by Cargo.lock.
Upstream copyright and the Apache-2.0/MIT license files are retained. This is
third-party code, excluded from the original GPL-2.0-or-later workspace members.
The project uses the upstream MIT option; this note does not relicense it.

Only `src/image.rs` differs from the imported package source. `CachedIcon`
retains the length of the exact raw/RGBA bytes already passed to `Cached`. Its
generated `include_bytes!` is assigned to `const BYTES: &[u8; N]` before the same
image constructor receives it. There is no byte substitution, extra allocation,
runtime I/O, unsafe, altered image dimensions or changed context/CSP/ACL logic.
Rustc checks that the real included file has exactly N bytes.

Import housekeeping: `.cargo_vcs_info.json` has a terminal newline added by the
patch tool; its JSON content is unchanged. All other imported text files were
compared to the registry source and are identical. The original `.crate`
archive SHA-256 was checked against crates.io:
`08279169ff42f8fc45a1dbc9dcae888893ba95288142e5880c59b93a26d2cfc5`.

Reason: the pinned Rust Analyzer 1.97 builtin `include_bytes` expands to
`&[0u8; _]`; a slice-only expected type leaves that array length unconstrained.
This caused E0282 in an otherwise rustc-checked Tauri context. The explicit
expected array type supplies the missing length without disabling diagnostics
or excluding generated code from analysis.

Source: [pinned include_bytes expander](https://github.com/rust-lang/rust/blob/1.97.0/src/tools/rust-analyzer/crates/hir-expand/src/builtin/fn_macro.rs).

Keep this narrow patch until the selected upstream codegen/analyzer combination
no longer needs it. Then remove the path override and this vendor directory,
and rerun actual analyzer clean/error/warning controls plus Windows/Android
builds before declaring it obsolete. `Cargo.toml.orig`, upstream README and VCS
metadata document provenance; no registry cache file was modified.
