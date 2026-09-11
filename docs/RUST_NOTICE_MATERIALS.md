# Rust license checks and retained original materials

## Current workflow: Cargo Deny

Following the user's September11 instruction, the authoritative Rust license
check is `cargo deny --locked --all-features --workspace check licenses` using
`deny.toml`. CI runs upstream cargo-deny0.20.2 through its commit-pinned Docker
action. Unaccepted or unidentified licenses fail the job; workspace, build and
development dependencies are included. No target or package exclusions are set.

Further bespoke notice/source searches and collection are stopped. The previous
scripts and already retained files below remain historical/reference material;
they are no longer called by the default quality workflow. Cargo Deny evaluates
crate declarations/inferred licensing against policy; its result is not a notice
archive or a corresponding-source publication.

## Historical original-material collector

The previous workflow kept Cargo's complete metadata inventory and ran the
bounded offline collector in `tools/license-materials.mjs`. Its output records
original material bytes, not license compatibility or distribution clearance.
It is not a corresponding-source archive or an npm/Maven/native-library audit.

When bounded package discovery misses original notice material,
`tools/license-upstream-policy.mjs` binds specific package names, versions,
literal license expressions and registry provenance to reviewed original
files. `third-party/notices/rust/sources.json` records each original URL, local
asset path, byte count and SHA-256. The collector fetches nothing; changed or
missing required files fail collection even if a local package notice exists.
Local notices remain included. Separate original paths retain separate records
even when their bytes happen to match.

Schema4 records per-consumer source relations, mandatory coverage/limitations
and an observed index digest. Repository assets use `upstream-repository`.
Selectors' separately referenced Mozilla MPL2 document instead uses
`referenced-license-document`, a null repository source path, document version
`MPL-2.0`, its exact official URL and the original643-byte `selectors/lib.rs`
header's source ID. BOTH original header and document are mandatory. The document
is not a Stylo Git file. No asset is represented as a file inside a crate that did
not contain it. The separate exact alloc-stdlib companion relation retains its
provider ownership and original pin; prior schemas are rejected.

The current explicit policy covers47 consumers and30 unique retained source
paths: the previous15 plus32 approved additions. There is no package-name prefix
wildcard or target filtering. All required files in a1/2/4-file group are checked
even when that package already has local notices. Local notices remain included.
Equal bytes across objc2, webview2 or UNIC revisions do not merge source paths,
URLs or material records. The imported file/index bytes are read offline and
gated by exact URL/length/hash pins; the collector never fetches replacements.

## Coverage is mandatory, not a legal-success flag

| Coverage | Material meaning and required boundary |
| --- | --- |
| `original-license-materials` | The exact reviewed original notice files were collected; global compatibility/source-completeness limitations still apply. |
| `header-and-referenced-license-document` | Selectors' actual header and the separately referenced, versioned Mozilla document; it cannot be relabelled as a Git repository file. |
| `upstream-license-explanation` | The four1339-byte objc2-family LICENSE.md files explain licensing; they are attribution/explanation, NOT complete MIT/Apache/Zlib terms. All19 consumers retain `full-license-terms-not-collected`, `apple-sdk-distribution-uncertainty-unresolved`, `no-license-option-selected` and `g002-legal-completion-not-proven`. |
| `original-mixed-license-notice` | The separate r-efi5.3.0/6.0.0 AUTHORS originals contain complete MIT text plus other notice passages, not full text for every declared alternative. That limitation and the unchanged triple expression remain explicit. |

The validator rejects changing or deleting a group's coverage/limitations,
reclassifying objc2 explanations as full terms, dropping the Apple SDK caveat,
breaking the Mozilla document/header relationship, or authorizing an unrelated
consumer. `collected` reports this original-material collection stage only.
Legal compatibility remains not evaluated, corresponding source is not produced,
and **G002 legal completion is not proven**, including when collection succeeds.

The objc2 scope is exactly the19 reviewed versions, with MIT retained for block2,
objc2, objc2-encode and objc2-foundation and the literal trio expression retained
for the other approved crates. r-efi remains
`MIT OR Apache-2.0 OR LGPL-2.1-or-later`; winapi GNU remains `MIT/Apache-2.0`.
AUTHORS is not globally promoted to license text by the r-efi-specific rule.

For the old winapi GNU0.4.0 packages, ROOT matched all2809 original files,
including2803 import libraries, against the historical9497609 source. Only
Cargo-generated normalized manifests were outside that original-file comparison.
The resulting historical notice association is retained without inventing an
archived VCS record or substituting a later same-version tree with changed notices.

## Bounded operation

The limits remain2048 packages,32 owned notice inputs/package,1MiB/file,32MiB of
material bytes and16MiB of exact serialized manifest bytes. The fixed repository
allowance is33 records (original3 plus the30 approved assets); per-consumer extra
references are bounded by the largest required group, not an unbounded exception
list. The output directory must be fresh, with no overwrite/recovery fallback.
Observed source/index/copy changes fail. Trusted, quiescent ROOT/CI trees remain
required: these checks are not atomic ancestor-swap/ABA containment.

ROOT verifies the retained files and archive/version associations. Static review
and fixture tests supplement that evidence; an SPDX declaration alone does not
authorize borrowing another package's notice. Files present on disk but absent
from the reviewed policy/index are not automatically included. Imported bytes,
including original line endings and attribution, are preserved by Git attributes.

Whole release membership, source completeness and unresolved upstream licensing
questions require separate review before publication. In particular, an
upstream explanation of licensing is not equivalent to complete license terms,
and collecting it does not resolve legal questions raised in that explanation.
