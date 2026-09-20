# Status projection implementation (2026-09-19)

## Findings

- Windows `AppRuntime::read_activity` always returned unavailable and snapshots always exposed an empty unavailable activity array, despite the exclusive service worker already owning an actual bounded activity journal.
- Android request catalog exposed only aggregate peer counts. `mobile/snapshot.rs` never populated `devices` or set device availability, so the connected-PC section remained unavailable even with an authenticated connection.
- The request decoder required a Korean literal computer label although native Android uses a localized resource. Non-Korean pending requests could therefore invalidate the entire request catalog.

## Changes

- Windows service samples its existing exclusive journal owner at most once per second; no second journal owner, new filesystem access path, or history mutation API is exposed to the GUI. The management snapshot carries up to 64 recent typed journal records, with a 12 KiB JSON bound within the existing 16 KiB frame limit. Local management codec advances to version 3; old codecs fail closed.
- Uninitialized/failed samples are `None`, not a successful empty history. Samples older than two seconds are withheld. Stopped/unavailable service snapshots clear the history availability. Explicit activity reads obtain a current service/management observation and do not reuse the last UI cache.
- Presentation maps only real `WindowsApplied` records to approved/denied. Signature verification and delivery are ignored as approval outcomes. Other supported fixed lifecycle/terminal/failure facts map to their corresponding labels. No prompt contents, command lines, keys, routes, or caller-controlled strings enter journal projection. Clear-history remains unsupported on PC.
- Android catalog version 2 includes a bounded per-PC list from the existing committed association ledger: public PC identity, registry revision, route-presence bit, and current native intake connection observation. Enrollment alone never sets connected. Aggregate connected count is computed from those same projected rows.
- Kotlin forwards only those public display fields. The strict Rust decoder checks length, canonical identity/revision, uniqueness, bounds and count consistency, projects PC labels, and only publishes device availability for a ready catalog. A final owner readiness observation invalidates devices alongside requests/history on stop/failure.
- Localized computer context labels now require bounded nonempty display text rather than a Korean-only literal; they remain presentation only.

## Added/updated source tests

- Management codec: unavailable versus empty versus 64 typed records; roundtrip; truncated frames; oversized history; invalid presence marker; explicit version-3 fixture.
- PC projection: phone signature/delivery do not count as Windows approval; actual applied approve/deny do.
- Runtime: known history, unavailable history, successful empty history and stopped service remain distinct.
- Android bindings: persisted peer starts disconnected; actual synthetic authenticated intake makes the same projected peer connected.
- Catalog decoder: malformed peer identity/revision/counts, disconnected peer, empty catalog and localized labels.
- Android shell snapshot: ready current owner publishes real device row; reconciling and final stopped owner withhold rows.

## Verification boundary

Only static source inspection and test authoring were performed by this child. No build, test, formatter, lint, Rust Analyzer, executable check or device QA was run. ROOT/CI must run the required gates and inspect actual native Windows/Android artifacts. These tests do not establish real UAC approval, phone authentication, USB hardware support, or native end-to-end results.
