# Rust original notice material collection

The quality workflow keeps Cargo's complete metadata inventory and runs the
bounded offline collector in `tools/license-materials.mjs`. Its output records
original material bytes, not license compatibility or distribution clearance.
It is not a corresponding-source archive or an npm/Maven/native-library audit.

For registry archives that omit a notice present in their original repository,
`tools/license-upstream-policy.mjs` binds specific package names, versions,
literal license expressions and registry provenance to reviewed original
files. `third-party/notices/rust/sources.json` records each original URL, local
asset path, byte count and SHA-256. The collector fetches nothing; changed or
missing required files fail collection even if a local package notice exists.
Local notices remain included. Separate original paths retain separate records
even when their bytes happen to match.

Schema3 records repository assets as `upstream-repository`, with per-consumer
source relations and an observed index digest. It never represents those assets
as a file inside a crate that did not contain it. The separate exact alloc-stdlib
companion-package relation retains its provider ownership and original pin.

ROOT verifies the retained files and archive/version associations. Static review
and fixture tests supplement that evidence; an SPDX declaration alone does not
authorize borrowing another package's notice. Files present on disk but absent
from the reviewed policy/index are not automatically included. Imported bytes,
including original line endings and attribution, are preserved by Git attributes.

Whole release membership, source completeness and unresolved upstream licensing
questions require separate review before publication. In particular, an
upstream explanation of licensing is not equivalent to complete license terms,
and collecting it does not resolve legal questions raised in that explanation.
