# ADR 0024: Service-owned pairing rendezvous after full SCM Ready

Status: accepted for implementation; native positive-path validation pending.

## Context

ADR0022 and ADR0023 provide fixed native clients and the live helper handoff.
Their server producer must share the original service/session ownership and
cannot treat an informational rendezvous as enrollment consent. STOP can be
latched before SCM has published StopPending.

## Decision

The entry thread issues a private, one-use full-Ready permit only after the
actual status report, post-report actions and original startup/stop checks.
The existing ServiceSession consumes it and owns the sole pairing producer.
Constructors otherwise remain dormant.

Two fixed idle listeners retain their original overlapped operations without
starting an attempt timer. Actual authenticated Starter admission captures one
five-minute window. Helper transfer keeps the same native operation, context
and deadline. Fallible transfers retain their owners on error for cancellation.

One slot retains a burned nonwrapping generation, a fresh nonzero public ID,
the original peer pair and engine epoch. Bound requires both expected messages,
the exact helper PID/creation claim, retained context identity, current WTS epoch
and live native peer rechecks. It conveys no reusable authorization.

The actual entry STOP latch gates positive native issues, completions,
publication and rearming; cleanup remains available. Thirty seconds reserved
from the original attempt budget allow the fixed Close/CloseAck exchange.
Both acknowledgements must be consumed while both peers remain live before
either endpoint closes. Failed/expired/stopped attempts cancel and drain.
All native owners remain accounted for before registry/key release; uncertain
cleanup cannot rearm or manufacture successful quiescence.

## Consequences and limits

The design adds no generic local signing, execution, approval or input API.
QR issuance, enrollment, GUI activation, fresh UAC ceremony authorization and
target-bound Windows application remain separate work. Native input-quiet
checks are snapshots, not an atomic guarantee against concurrent incoming data.
STOP cannot retract already delivered bytes or preempt an entered Windows call.

Deterministic fixtures exercise policy/ownership transitions, not a real
positive SCM/client/UAC session. ROOT alone runs validation; local native
elevation remains subject to the user's separately scoped authorization.
