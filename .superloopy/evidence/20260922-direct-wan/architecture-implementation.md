# A1 implementation receipt

ROOT approved A1 in `architecture-approval.md`; the same fresh architecture
reviewer implemented only that selected plan. No child implementation agent was
used. The permitted explorer remained read-only and found no second candidate.

## Implemented

- Added private `direct/obligations.rs::MappingObligations`. It owns active and
  displaced grants, exact-path selection, granted-expiry retirement, capacity,
  retry timing, renewal, read-only fallback probes and cleanup acknowledgement
  disposition. Collections and policy do not escape to the polling caller.
- `direct.rs::run` now passes each discovery observation to that owner and reads
  its optional candidate projection. The final shutdown consumes the same owner
  and uses its same path-selection transition before one existing bounded PCP
  release. This includes an already-owned displaced grant when its exact route
  has returned; no new mapping is created during shutdown.
- The PCP encoder, parser, nonce derivation, transport, deadlines and real UDP
  fixture source are unchanged. A `cfg(test)` synthetic lease constructor enables
  ownership lifecycle fixtures without a real router or mapping side effect.
- Added the Mapping obligation term to CONTEXT using its existing bullet format.
  The skill's linked `grill-with-docs/CONTEXT-FORMAT.md` was unavailable; no alternate
  instruction was invented. ADR0038 already records the applicable decision.

## Authored test surface (not executed)

Eight tests in the ownership module exercise its production transitions:

1. Actual `poll` handles missing/cancelled routes while retaining known grants.
2. Changed path withdraws candidates; exact restoration remains cleanup-only.
3. IPv6 candidate rotation preserves mapping; local tuple changes displace it.
4. A 7200-second grant survives beyond the requested 600-second interval.
5. Four total obligations prevent new maps while permitting exact restoration.
6. Failed cleanup retains ownership; confirmed cleanup retains the 120s backoff.
7. Shutdown selects one exact restored path, retaining unrelated displaced paths.
8. Unknown, wrong or expired paths cannot supply a shutdown cleanup target.

Tests use the same selection/admission/cleanup-completion/final-selection methods
that production polling and shutdown call. Internal state is arranged only to
represent previously accepted synthetic leases. These source fixtures do not
claim actual router disappearance, outside-network connectivity or native auth.

## Preserved invariants and integration

Maximum four obligations; original returned expiries; cleanup-only grants never
advertised; exact internal IPv4/gateway identity; same-server nonce behavior;
no old-router operation through another route; existing bounded I/O and cancelled
positive-map admission; existing retry delays. No public interface, wire format,
key, pin, request lifetime, denial scope, UI or management behavior changed.

No validation commands were run: ROOT must execute format/Clippy/tests and all
required CI gates on the integrated exact commit. ROOT's concurrent Android
CommitReceipt/diagnostic fixes were not edited. Product files for this slice:

- `CONTEXT.md`
- `crates/relay-service/src/direct.rs`
- `crates/relay-service/src/direct/obligations.rs` (new)
- `crates/relay-service/src/direct/pcp.rs` (test-only constructor)

No commits or pushes by this reviewer. No validation claim is inferred from this
receipt. ROOT owns the post-refactor static review, exact-source CI, publication
and the remaining real outside-network acceptance work.
