# Final architecture candidates — 2026-09-19

Baseline: `a2c192fe01fc0ba456d966e59fb66e621331f432`.
Skill used: `improve-codebase-architecture`, including LANGUAGE and HTML-REPORT.
Read CONTEXT and relevant ADR0014, ADR0018, ADR0020, ADR0026, ADR0033.
CONTEXT's implementation-status paragraph is historical; current source is the
implementation evidence, not a renewed claim that native acceptance passed.

HTML report (OS temp, unique path):
`C:/Users/32170336/AppData/Local/Temp/architecture-review-20260919T213825790.html`

## Candidate 1 — Strong — deepen live Prompt Request lease

Files: `crates/windows-service-host/src/peer_runtime/prompt.rs`,
`crates/windows-service-host/src/peer_runtime.rs`,
`crates/windows-service-host/src/peer_runtime/tests.rs`.

PromptState currently exposes live/take/replace/live_mut around a fully mutable
LivePrompt. Renewal coordinates binding, request ID, issue time, deadline and
previous binding in the caller. Reconnect independently recreates the same
Opened/Renewed event choice. Deepening means hiding coherent lease transition
and publication facts behind the live Prompt Module's Interface, not extracting
the same statements to another file. Engine/native/transport ownership stays put.

Preserve exact Request identity/content, engine-issued fresh nonce, no revival,
consumed/applying fence, 110-second lease/30-second margin, signed Renewed
discriminant on reconnect, and current publication-failure cancellation.
Existing ServiceSession test Interface remains; add focused Module tests.

## Candidate 2 — Worth exploring — retained Request suppression lifecycle

Files: `crates/phone-request-core/src/inbox.rs`, `checkpoint.rs`,
`checkpoint_codec.rs`, `tests/renewal.rs` in the same crate.

Ten coordinated retained fields are rewritten in admission, renewal, effects and
restore. A deep lifecycle Module could concentrate body/recovery/terminal/lineage
invariants. This is substantially riskier immediately after the legacy-source
suppression fix. Recommend deferring it in this finalization. No checkpoint-format,
source-expiry, receiving-generation, effect-order or terminal-outbox changes.

## Deliberately retained

USB framing and separate medium-integrity native courier already form a real
Seam; cosmetic splitting has no Depth. Public invitation carrier authorization
and ADR0020 supersede ADR0026's historical invitation-confidentiality rationale
only for that public data. Protected comparison and all enrollment authority,
native confirmation, replay and original ceremony lifetime invariants remain.
Native platform status projections retain distinct owners and unavailable states;
do not force them into a generic shared availability abstraction.

## Selection gate

Recommend candidate 1 only. No product edits have occurred. ROOT selects and
answers design questions under the user's explicit delegation, then authorizes
this same agent to implement exact files. ROOT/CI alone runs validation. No child
builds, tests, lint, fmt, executable or native QA were run for this report.
