# Release notes implementation receipt

Date: 2026-09-21
Owner: ROOT's release_notes worker
Status: implementation and static review complete; ROOT/CI validation pending.

## Changes

- Removed the growing historical feature list and the long verification table
  from `docs/RELEASE_NOTES_TEMPLATE.md`.
- Moved verification scope, historical alpha.13/alpha.40 evidence, the 2026-09-19
  user report, and deferred new-install UAC/phone-auth/device checks to
  `docs/release-verification.md`. The release links to this exact commit, not main.
- Every release attaches `release-verification.md`, generated with version,
  exact build SHA and previous published-release tag at the top.
- Notes query all pages of non-draft published GitHub releases under the existing
  publication concurrency lock. Both stable and prerelease tags participate.
  Full Git history is required; published tags must resolve. The nearest reachable
  published ancestor bounds `git log <previous>..<current>`. Unpublished tags,
  drafts and unrelated/future branch releases do not advance the boundary.
- Notes show at most eight non-merge/non-release-metadata commit subjects plus
  an exact-SHA compare link. The initial-release case links exact-SHA history.
  Commit subjects are escaped and do not re-enter template interpolation.
- Publishing retains existing immutable-tag, signer, and exact-commit gates.
- Corrected a carried-forward table inconsistency: public diagnostic files permit
  read access and deny writes; protected original journals deny read access. This
  matches the existing detailed diagnostic paragraph rather than its old table's
  contradictory claim that both public read and write were denied.

## Authored regression coverage (not executed by this worker)

`node --test tools/release-notes.test.mjs` covers paginated published release
selection, ancestor distance, an actual temporary Git repository across successive
releases (no repeated prior change), unpublished versus published prerelease
boundaries, stale checkout/missing tag failures, bounded summaries, Markdown/HTML
escaping, immutable verification links, no second-pass interpolation, metadata
validation, retained evidence scope and workflow asset/full-history wiring.

ROOT must run these through the permitted CI path. No build, test, formatter,
lint, executable validation, Git commit, push, or GitHub mutation was run by this
worker. No children were spawned.

## Files

- `tools/release-notes.mjs`
- `tools/release-notes.test.mjs`
- `docs/RELEASE_NOTES_TEMPLATE.md`
- `docs/release-verification.md`
- `docs/stable-release.md`
- `.github/workflows/release.yml` (notes checkout/env/generation/asset list only)
