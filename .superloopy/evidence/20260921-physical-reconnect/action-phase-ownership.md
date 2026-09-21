# Native action phase ownership (M3)

Implemented in the working tree after instrumentation commit `3c3d4e6`.
Child performed source inspection and edits only. No build/test/lint/formatter,
device operation, commit or push was run. ROOT/CI owns validation and integration.

## Changed boundary

`NativeActionGeneration` and `NativeActionPhaseOwner` are native callback
presentation ownership, distinct from `NativeDecisionObservation` and optional
diagnostic data. Each request entry retains one current admitted generation.
The registry installs it only after the unchanged approval coordinator returns
true or the unchanged denial coordinator returns WAITING (retained native job).
A candidate created for a rejected/BUSY action does not become the owner.

Every phase callback carries that generation. The registry requires the exact
current locator, active entry and owned generation before changing entry.phase.
Stale Prepared callbacks also cannot install a delivery into a newer action;
their submission uses the existing bounded close path. Retained deliveries carry
their native generation and separate diagnostic token through driver progress.

PENDING terminal cleanup releases only the matching generation. An old cleanup
cannot release a newer owner. UNAVAILABLE remains owned because native uncertain
cleanup can still report RELEASED; no unproven completion is introduced.
Withdrawal/retirement permanently closes the old phase owner. A replacement
entry gets ownership only for a still-current retained delivery, and callbacks
must still address the replacement's locator. Old entry callbacks cannot mutate
the replacement. Native request/lease checks remain unchanged.

## Admission ordering and locks

Approval admission occurs on main and denial admission on the single actor
worker. A separate per-entry actionAdmissionLock serializes those bounded native
admission calls plus phase-owner publication, preventing an older returned
admission from publishing after a newer accepted action. It is never acquired
by callbacks or while holding registry/entry locks. Native request checks happen
before it. No signing, storage, hardware-auth prompt or waiting for another
executor occurs inside it: the existing request methods perform admission and
queue work. Optional measurement registration uses only bounded body-free native
identity calculation and monotonic observation.

Synchronous rejection callbacks can occur before candidate activation. Their
generation is not owned, so they cannot modify the prior phase. Successful
approval callbacks resume through main after the current main admission returns;
successful denial work runs on the existing worker after its current admission
job returns. No callback acquires actionAdmissionLock. No registry lock spans
either native request admission call.

The phase owner does not replace denial blockers, Rust signature/expiry/replay
checks, Activity ownership or actual coordinator admission. Diagnostics cannot
install a phase owner or grant authorization. DenialJobs is unchanged.

## Synthetic tests added (not executed)

- Approval then denial: late approval cancellation/preparation/progress and
  terminal cleanup cannot own or release denial's generation.
- Rejected/BUSY candidate cannot replace the already admitted owner.
- A synchronous candidate rejection callback before publication cannot change
  the existing phase; an old-owner callback during newer admission is overwritten
  by the new initial phase, and rejected after the new generation publishes.
- Terminal generation cannot report new progress; a newly admitted retry can.
- Retired request entry cannot be reopened by callbacks/admission.
- Replacement transfers only the current retained delivery's ownership.
- Superseded/missing delivery does not acquire replacement ownership.

These JVM tests exercise the pure ownership rule, not real Android callbacks,
authentication, native requests or Windows behavior. ROOT must run CI and review
the integrated native callback paths before the feedback UI ships.

The independent reviewer confirmed the scheduler/lock invariants by source
inspection. No callback buffer was added: that would duplicate Prepared-wrapper
cleanup ownership for an interleaving the current main/single-worker scheduling
already excludes. If these native request methods are later changed to deliver
successful callbacks on a different executor or inline, generation publication
must move into that admission boundary or use a resource-owning callback gate.
