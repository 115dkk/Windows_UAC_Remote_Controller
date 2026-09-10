# Android lifecycle dependency patch set

Status: patch implementation in progress; not an acceptance record.

ROOT reproduced a real product failure at e423727 / CI34491620757: after actual
native shutdown and Activity finish, the next genuine MainActivity had no
attached WebView. Initial load, configuration recreation and native shutdown
completed before this failure. Preventing implicit process exit preserves the
background owner but cannot alone restore the presentation window.

The public pinned APIs select an available Activity or create a new Activity;
they cannot require a particular existing registration. Android IPC also loses
physical-view identity before queued mobile plugin commands reach Kotlin. The
patch must provide explicit existing-Activity attachment plus immutable native
view provenance, while retaining the existing controller/authentication owners.

## Upstream source provenance

ROOT extracted only the following locally cached official crate archives after
checking each SHA-256 against Cargo.lock and checking every archive member path.
No version upgrade, package-source replacement or registry-cache edit occurred.
Original package licensing and notices are retained.

| Package | Official crate SHA-256 |
| --- | --- |
| tao 0.35.3 | d1c93047acf68669466a34690ac58cca7010bd1b201e1ec86f1fd0a75d3dd4a9 |
| tauri-runtime-wry 2.11.4 | 4e6fac707727b7a2f48e4ded90976324267371073edbb415ffb73bb0458d203f |
| tauri 2.11.5 | 667b20e2726d572dea2de7370da16e188eb06008faf9a92fab7cdc46791190b5 |

Existing vendored wry 0.55.1 retains its own LOCAL_PATCH.md history.

## Licensing of this local patch set

Original upstream portions retain their existing licenses/notices: Apache-2.0
for Tao, and Apache-2.0 OR MIT for Tauri/runtime-wry/Wry. Original material added
for this project's physical-origin/lifecycle patch is GPL-2.0-or-later. The
patched package metadata uses an AND expression to record both sets of terms;
the untouched Cargo.toml.orig files remain provenance, not the patched metadata.
The original workspace licensing remains GPL-2.0-or-later.

Source: [SPDX conjunctive license expressions](https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/#d43-conjunctive-and-operator).
Tao's Apache-only upstream code already preceded this patch. Combined release
binaries including it require the compatible GPLv3-or-later distribution route,
not GPLv2-only; the source's or-later grant permits that route. Release notices,
license copies and corresponding source still need the final distribution gate.
See [Apache's GPL compatibility explanation](https://www.apache.org/licenses/GPL-compatibility.html).

## Required invariants

- First-party Rust continues to forbid unsafe. JNI ownership remains within the
  Android-only dependency boundary and must have explicit lifetime reasoning.
- Attach only to an opaque lease minted from actual native Activity registration.
  No ID/string/JSON reconstruction, fallback Activity selection, automatic
  Activity launch, polling, stale-reference reuse or forced UI opening.
- A physical Activity/WebView generation is different from a logical window ID.
  Destruction invalidates only the original generation; queued creation and IPC
  work retain and recheck their original generation before use.
- Carry native physical origin through both IPC paths, Rust command admission,
  worker queues and the mobile plugin call. Serialized input cannot supply origin.
- The per-Activity presentation adapter is immutable. Old work never acquires
  a replacement host. Native request binding, expiry and authentication checks
  remain the authority for actual approval.
- Build success is not attachment success. ROOT must run exact-commit Android
  compilation and real product close/relaunch, recreation and background tests.

Patch file inventory and final root verification are added when implementation
is frozen; this document currently grants no passing lifecycle criterion.

## Host Analyzer compatibility

The path-vendored crates are included in the same strict real Analyzer scan as
the application. Upstream synchronous menu/icon resource work is kept in private
synchronous callees of the original async commands, retaining lock spans and
native operation order. HTTP method matching borrows the method text; tracing
statements use feature-gated blocks. Native Xlib pointer types are explicit and
divergent branches are flattened without changing event dispatch. These changes
address concrete Linux/Windows diagnostics without disabling diagnostic classes
or excluding third-party paths. ROOT runs a fresh scan after changes.
