# ROOT architecture selection

2026-09-19; reviewed architecture-candidates.md and the complete temporary HTML
report from the fresh final_architecture agent. Selection: approve candidate C1
only (deepen live Prompt Request lease). Defer C2 retained phone state because it
would broaden durable migration/suppression risk after that slice's security fix.

Approved ownership: windows-service-host/src/peer_runtime/prompt.rs,
peer_runtime.rs, peer_runtime/tests.rs, plus bounded domain/ADR clarification and
the implementation receipt. ROOT continues independent CI/tooling fixes.

Design decisions/invariants:

- LivePrompt privately owns correlated binding, issue/deadline and renewal
  predecessor facts, exposing coherent lease replacement and publication.
- ApprovalEngine remains the sole nonce/authorization/eligibility owner.
- Native observation remains outside the module; no new way to assert liveness.
- Same RequestId/content/eligible devices; fresh nonce; exact old signature
  invalidation; 110-second lease and30-second delivery margin unchanged.
- Consumed/applying/expired requests cannot renew. Failed publication retains
  existing cancellation/error behavior. Reconnect must retain Renewed, not turn
  it into Opened and bypass unknown-renewal suppression.
- No protocol, checkpoint, transport, Android native lifecycle or UI redesign.
- Existing ServiceSession Interface tests remain; focused new module tests may
  be authored. No child validators. ROOT refreshes source hashes only after
  final static comparison and formatter, then verifies exact-commit CI.

The SAME architecture agent may now implement C1. Further semantic changes or
uncertain proposals must return to ROOT for approval before edits.
