<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Scoped architecture result: native connection and measurement delivery

Date: 2026-09-21. Source reviewed: `ddadc7d..a1c5ae8d925486d13964cb3b38966d4979f39324`.

ROOT approved the **no product refactor** recommendation after reviewing the complete candidate receipt and HTML. Selection and conditions are recorded in `architecture-approval.md`. The scoped architecture review is complete; no product implementation, new interface, domain term or ADR was introduced.

The current modules retain useful depth and locality: Android default-network observation remains separate from admitted Rust generation cancellation; bounded Decision observation remains independent of native action-generation phase ownership; canonical receipt identity stays in Rust; the one-off same-signer measurement lane retains its narrow trust and artifact contract. The small retained-delivery field grouping opportunity did not justify changing reviewed native lifetime behavior.

Process evidence: the reviewer fully read the architecture skill, glossary and HTML reference, CONTEXT.md and ADRs 0014/0015/0027/0031; one bounded read-only explorer independently inspected measurement/phase ownership and concurred. Candidate report: `architecture-candidates.md`. HTML: `C:/Users/32170336/AppData/Local/Temp/architecture-review-20260921-230343.html`, opened through the default handler. No build, test, lint, formatter, executable/device QA, private state/key/journal read, commit or push was performed by the architecture reviewers. Only these architecture report artifacts were written.

This is the architecture gate for the current native connection/measurement delivery, not whole-product completion. ROOT owns exact-commit CI and prerelease verification. The real default-network callback/TCP recovery evidence in `physical-trial-02.md` applies to installed candidate `c48598a`, not a completed physical authentication sample or all transport readiness. Actual phone authentication and Windows application remained unconfirmed. Measurement-dependent feedback UI remains DESIGN ONLY and awaits a valid controlled sample/user readiness. A reachable public external relay path remains an authority/deployment prerequisite for the outstanding mobile-WAN objective; this review expands neither deployment nor authentication authority.

SUPERLOOPY_EVIDENCE .superloopy/evidence/20260921-physical-reconnect/architecture-result.md
