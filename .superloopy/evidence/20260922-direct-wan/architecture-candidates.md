# Direct-WAN final architecture candidates

Date: 2026-09-22. Reviewed baseline: `8be9af9`; reviewed product HEAD:
`3391008b8972500e4fdc6f77c204c18fa6933e26`, plus uncommitted ADR0038.
Fresh final architecture reviewer; source inspection only. No builds, tests,
formatting, lint, device/network QA, commit or push executed by this reviewer.
ROOT owns validation and selection. This is the pre-selection candidate record;
subsequent A1 approval and implementation are recorded separately in
`architecture-approval.md` and `architecture-implementation.md`.

Read the complete improve-codebase-architecture skill, LANGUAGE and HTML-REPORT,
CONTEXT, ADR0014/0015/0031/0038, direct-WAN security review and current production
source. CONTEXT/older ADR implementation-status paragraphs are historical;
current code and actual evidence control the implementation verdict.

## A1 — Concentrate mapping-obligation ownership

Recommendation strength: **Worth exploring**. Category: **in-process**.

Files:

- `crates/relay-service/src/direct.rs:238`: direct gateway polling implementation.
- `crates/relay-service/src/direct.rs:255`: expiry and route-displacement rules.
- `crates/relay-service/src/direct.rs:289`: same-path obligation restoration.
- `crates/relay-service/src/direct.rs:308`: capacity and mapping admission.
- `crates/relay-service/src/direct.rs:379`: shutdown only considers active lease.
- `crates/relay-service/src/direct/pcp.rs:18`: owned nonce/expiry/cleanup-only lease.
- `crates/relay-service/src/direct/tests.rs:17`: mapping-path comparison fixture.
- `crates/relay-service/src/direct/pcp.rs:422`: UDP cleanup acknowledgement fixture.

Problem: the direct gateway module is externally deep, but its internal mapping
obligation interface is shallow: the polling implementation manually coordinates
an active tuple and displaced tuples, while shutdown duplicates only part of that
ownership knowledge. A route restored immediately before cancellation can leave
the matching displaced obligation outside the one final cleanup attempt. The
security audit already identifies that limited cleanup edge. Current test sources
exercise path equality and PCP operations separately, not the lifecycle that
connects displacement, restoration, capacity, expiry and shutdown.

Solution: concentrate active/displaced obligation ownership in one private module
used by both ordinary polling and shutdown. Keep PCP wire I/O and its existing
nonce checks intact; the new implementation owns path selection, expiry,
cleanup-only transitions and bounded admission. Do not merely extract a pure
predicate or expose the underlying collections through pass-through accessors.
No concrete interface is proposed before ROOT selection.

Before: polling owns active/displaced/path/capacity state → PCP lease; shutdown
owns separate active-only selection → PCP lease. After: polling and shutdown
cross one private mapping-obligation seam → retained exact-path PCP lease.

Benefits:

- Locality: one mapping ownership implementation.
- Leverage: normal and shutdown paths agree.
- Tests cross the production ownership interface.
- Path restoration becomes directly exercisable.

Deletion test: removing the proposed module must put route selection, bounded
admission and retained-obligation transitions back into both polling and shutdown;
if the design instead leaves those decisions in the callers, reject it as a
shallow pass-through. A generic router adapter hierarchy is unnecessary: PCP is
the only mapping-mutating adapter, and NAT-PMP/IGD are read-only observations.

Conditions before implementation:

1. ROOT approves the scope and the limited behavior improvement: a single bounded
   final attempt may select an already-owned displaced lease on its exact restored
   path. No new mapping, unrelated route or other application's map is touched.
2. Maintain capacity, expiry from the returned grant, cleanup-only publication
   withdrawal, same-server nonce continuity, cancellation and all retry bounds.
3. Tests must exercise the shared production seam for changed/restored route,
   expired obligation, capacity, cleanup failure retention and shutdown selection.
   Preserve the real UDP fixture source; synthetic results remain distinct from
   actual router evidence. ROOT runs tests in CI.
4. Keep changes confined to the relay direct implementation/tests and concise
   domain/ADR evidence as required; no public signing, auth or UI change.

ADR alignment: reinforces ADR0038's exact-owned finite mapping obligations; does
not reopen ADR0014/0015 request/denial semantics or ADR0031 embedded ownership.
Risk: moderate refactor sensitivity because these ownership rules are new; this
is not an authentication bypass fix or a release prerequisite by itself.

## Deliberately retained architecture

- The gateway owner already hides discovery, bounded I/O and lifecycle behind
  `start`/`snapshot`/`cancel`/`drain`. Splitting it only by file size adds no depth.
- Signed address exchange and the durable routing book must remain separate:
  the former owns nonce/epoch/socket freshness; the latter stores generation-
  scoped untrusted coordinates with no request, key or freshness authority.
- Initial pairing selection and steady-state reconnect have different signing
  and admission lifetimes. A shared generic retry module would enlarge the
  interface and obscure the pre-sign fallback stop condition.
- Read-only QueryDirect preserves legacy Snapshot bytes and an optional deadline.
  Unifying those formats is not a deepening opportunity.
- PCP, read-only IGD HTTP/XML and canonical address codecs concentrate different
  protocol facts. Collapsing them would disperse rather than improve locality.

The one permitted read-only explorer independently inspected Android address
exchange, routing persistence, checkpoint, connectivity and Windows publication.
It recommended retaining that area: removing a seam would spread socket
freshness, storage generation, carrier retry or signing authority into another
module. It found no duplicated policy owner warranting a second candidate.
The explorer performed source inspection only and spawned no children.

## Top recommendation and decision gate

Select **A1 only** if ROOT wants the exact-path shutdown selection and lifecycle
test surface in this release. Otherwise retain the current architecture, record
the known bounded cleanup limitation, and proceed with exact-commit CI/native
acceptance work. There is no second worthwhile candidate in this scoped review.

HTML report: `C:/Users/32170336/AppData/Local/Temp/architecture-review-20260922-042400.html`.

No outside-network connection, actual phone authentication or Windows UAC outcome
is established by this report. Architecture completion does not complete the
overall remote-UAC objective. User questions are delegated to ROOT under the
project instructions; the initial decision gate was followed before implementation.
