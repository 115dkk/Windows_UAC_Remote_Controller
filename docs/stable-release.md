# Main-driven stable releases

Merging into `main` starts **Main stable release**. The first stable version is
`1.0.0`; alpha tags do not change that starting point.

For later main changes, the strongest Conventional Commit signal since the most
recent reachable stable tag determines the bump:

| Change record | Bump |
| --- | --- |
| `type!:` / `type(scope)!:` or `BREAKING CHANGE:` footer | major |
| `feat:` / `feat(scope):` | minor |
| Other changes, including `fix`, docs and unclassified commits | patch |

Use a matching PR title/commit message so the automation can classify intent.
The algorithm is deterministic; it does not infer compatibility from a source
diff or an AI opinion. It never increments once per job or per retry.

The workflow commits only the five version metadata files, using ordinary
fast-forward Git. It then explicitly dispatches ten existing checks for that
exact commit, including Rust Analyzer/Clippy/licenses, Android startup/lifecycle,
native Windows QR/denial, installer geometry, UI and packages. This explicit
dispatch is necessary because `GITHUB_TOKEN` pushes do not trigger workflows.

Only a green exact-SHA set creates a new stable tag and starts **Release**.
Release independently checks the same gates, builds signed Android and Windows
assets and publishes without `--prerelease`. Explicit hyphenated tags remain
prereleases. Existing published assets/tags are never overwritten.

Publication is serialized across tags. Inside that critical section, semantic
version comparison over all published releases decides the Latest marker. An
older package which finishes later can publish its own immutable assets without
moving Latest backward. Prereleases and drafts do not advance that marker.
GitHub concurrency is not FIFO: a superseded pending publication can be cancelled
and remains unpublished. Retry that exact existing tag; cancellation is not success.

A concurrent main update rejects the stale push/dispatch/tag handoff. The next
queued main run handles the newer head. An existing prepared metadata commit can
be reused after a failed check; a follow-up fix with already-correct metadata is
verified at its own HEAD without requiring an empty commit. A tagged-but-unpublished
HEAD retries that exact version on manual Main stable release dispatch. Do not
edit an already published tag. If packaging
fails after tagging, rerun the failed Release job or dispatch Release for that
same existing tag while it is still unpublished, using `--ref <that-tag>` as
well as the `tag` input. A published release is final.

The workflow needs repository `contents: write` and `actions: write`. Protected
branch rules must permit the normal release metadata update; do not bypass a
branch protection failure. Native test scope and limitations remain in the
commit-pinned `docs/release-verification.md` linked from release notes, with a
version/commit-bound copy attached to every release, regardless of naming.

Release notes list at most eight recent non-merge changes after the nearest
reachable **published** release (stable or prerelease), plus a full comparison
link. The publication job fetches full Git history and queries every page of
published releases under its publication lock. Drafts, unpublished tags and
unrelated/future branches do not advance that boundary. Release metadata-only
commits are omitted. The template contains no persistent feature bullet list:
past changes cannot accumulate across successive releases. If no release is an
ancestor, the first-release summary links to that exact commit's full history.

Stable Android publication requires all persistent keystore secrets and the
public certificate fingerprint in `security/android-release-signer.sha256`.
That fingerprint was verified against alpha.40's published APK. Missing secrets
or a changed signer fail publication instead of generating an incompatible key.
Intentional key rotation requires an explicit Android signing migration.
