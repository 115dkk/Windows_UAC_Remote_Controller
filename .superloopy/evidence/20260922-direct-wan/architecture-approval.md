# ROOT selection: A1 mapping obligations only

ROOT reviewed the fresh architecture candidate report for3391008 and approves
A1: one private production mapping-obligation owner shared by polling and
shutdown, with the limited improvement that shutdown may select one already-
owned displaced lease on its exact restored path for bounded cleanup.

Conditions: preserve total capacity4, actual granted expiry, cleanup-only
withdrawal, server/path nonce scoping, cancellation, retry bounds and existing
PCP wire validation. No new mapping or foreign mapping at shutdown. No public
authority, generic router trait, crypto/pin/request/denial/UI change. Tests must
cross the same production seam for displacement/restoration/expiry/capacity/
failed-cleanup retention and final exact-path selection. ROOT runs all CI.

Reject a collection accessor/predicate extraction that leaves ownership policy
in callers. Keep other modules unchanged. The same architecture agent receives
this decision and implements only this bounded plan; user questions are delegated
to ROOT. This scoped approval is not a completed WAN or authentication proof.

At this final review boundary, a fresh general usage reading reported96percent
used. The prior Claude handoff was already completed, and the latest user
explicitly requests uninterrupted resumed work. No repeated handoff, reset credit
or budget-phase exception is claimed. Product implementation is complete apart
from CI corrections and this actual final-refactoring pass.
