# Final architecture implementation — C1 only

ROOT selected C1 in `architecture-approval.md`; C2 (phone retained suppression
lifecycle) remains deferred. The same final architecture agent implemented the
approved scope after candidate-report approval.

## Source ownership and depth

- `crates/windows-service-host/src/peer_runtime/prompt.rs`: private `LiveLease`
  retains binding, issue time, monotonic deadline and immediate predecessor.
  `LivePrompt` owns coherent replacement, publication/resolution construction,
  renewal eligibility, exact authorized-context matching and the dispatched-action
  latch. It has no engine, signer, transport, native liveness probe or native action.
- `crates/windows-service-host/src/peer_runtime.rs`: initial publication, renewal
  and reconnect share `LivePrompt::publication`. Engine renewal and all existing
  failure/cancellation branches stay in the original serialized owner.
- `crates/windows-service-host/src/peer_runtime/tests.rs`: existing interface tests
  adapted to private state; two focused LivePrompt interface tests and a renewed
  publication assertion added. Tests use the existing synthetic engine fixture,
  not direct construction of the new private lease record.
- `CONTEXT.md`: narrowly clarified the existing Request lease domain concept.

Deleting the new coherent lease implementation would put previous/current lease
assembly back in both renewal and reconnect callers. This is locality/depth,
not a file extraction or a new generic abstraction.

## Invariants retained by static comparison

- Exactly the original 110-second TTL and 30-second renewal margin.
- Fresh native same-content witness stays external; no renderer-supplied liveness.
- ApprovalEngine remains the sole nonce, eligibility and authorization owner.
- Renewal still uses the exact previous engine binding and cannot revive a
  consumed, applying or expired request. No changes to engine checks or expiry.
- RequestId now derives from the private binding, eliminating a duplicate mutable
  value. The original session-id duplicate is removed: initial challenge/session
  equality is still checked before construction, renewal preserves that session,
  and authorized matching compares the entire RequestBinding and zero logon ID.
- Content, native target and digest stay on the live Prompt; renewal replaces
  only the lease record. Dispatched-action state remains exact-target/binding,
  rejects repeats and prevents renewal. The existing native call order is intact.
- Opened/Renewed construction is shared across initial, renewal and reconnect
  publication. A twice-renewed request retains the immediate predecessor, not its
  original lease. Resolution always uses the current lease's binding/issue time.
- Publication failure, engine-renewal failure, native failure and shutdown retain
  original error/cancellation behavior. No new runtime panic path was introduced.
- No wire/checkpoint/Android lifecycle/UI/native-handle/protected-comparison edits.

## Authored tests and review

`live_prompt_interface_keeps_publication_and_resolution_on_one_coherent_lease`
covers original publication, exact timing gate, wrong target, expiry, two renewals,
stable identity/content/native facts, repeated reconnect publication and current
resolution. `live_prompt_interface_fences_exact_dispatched_action_without_rebinding`
covers wrong-target rejection, exact latch, repeat rejection and renewal fence.
Existing `fresh_same_prompt_witness_renews_before_expiry_without_resolving_the_prompt`
now also inspects the retained Renewed publication.

Independent read-only explorer reviewed the final three-file diff and found no
concrete behavior/security issue. Main architecture agent reviewed the static diff
and callsites. Neither agent ran tests, builds, lint, fmt or native/executable QA.
ROOT owns formatting, proof source-binding/hash updates and exact-commit CI.

The user has confirmed existing real-phone authentication and actual Windows UAC
acceptance (`user-acceptance.md`). These authored source tests are separate from
that evidence; new USB physical/driver combinations remain unverified.

## Skill execution

`improve-codebase-architecture`, LANGUAGE and HTML-REPORT were read and followed:
domain/ADR-first exploration, bounded read-only explorer, unique OS-temp HTML
candidate report, ROOT selection gate, same-agent implementation and receipt.
Optional linked `grill-with-docs/CONTEXT-FORMAT.md` and `ADR-FORMAT.md` were absent;
the narrow glossary addition follows the repository's existing format. No new ADR
or changed product decision was required.
