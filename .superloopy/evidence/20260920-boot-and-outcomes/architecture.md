# Alpha.39 final architecture candidate review

Date: 2026-09-20. Author: fresh alpha39_architecture child.
Baseline: `2926af0301b0e7f7b37a22083ba716bbcaa0c939` (alpha.38).
Initial reviewed HEAD: `858883aad28b90856d973c36af632f3baec5d196`.
Latest reviewed HEAD: `831aacbc69a2780ca70e97ea7f39adfe869b70ad`.
The intervening changes add explicit React hook fixture generics and await the
actual asynchronous fake-clock updates; inspected. The explicit durable removal
receipt/result check was already present in the product source reviewed above.

## Selection status

**Completed selection: ROOT approved no additional product refactor.**
No product source edits were made. No build, test, formatter, lint, executable
check, native action or device QA was run. ROOT owns CI and release completion.

ROOT accepted the deletion-test/locality analysis on 2026-09-20: the current
notification refresh queue/error policy and shared display hook earn their keep;
extracting orchestration would widen the shared admission/cleanup interface, and
a public shared outcome codec would couple distinct durable formats. ROOT directed
preserving source, requirements and security invariants, with no further product
edit or validator execution by this agent. This bounded current-delivery judgment
does not need a new ADR. The same architecture agent recorded this approval after
the candidate report; selection was not inferred or performed early.

Candidate HTML (OS temp, not repository):
`C:/Users/32170336/AppData/Local/Temp/architecture-review-20260920-121903.html`.

The `improve-codebase-architecture` skill, LANGUAGE.md and HTML-REPORT.md were
read in full. CONTEXT.md, implementation/security receipts, and ADRs 0001, 0005,
0006, 0009, 0011, 0014, 0015, 0019 and 0033 informed the review. Historic
implementation-status prose does not override newer reported real approval
observations or current implementation. No requirements or accepted ADR changed.

The skill's read-only exploration step used one bounded explorer,
`alpha39_architecture/notification_locality`, for the Kotlin action/refresh slice.
It reported independently before this recommendation; no edits or validators.

## Candidate examined — notification refresh orchestration

Strength: **Speculative; retain current shape**. In-process dependency category.
Paths below share `src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/`
unless otherwise specified.

Current friction: `background/NativeRequestCoordinator.kt:174–301` combines
action admission and fresh notification presentation after definite no-admission.
A possible new module would take the refresh scheduling/publication implementation.
However, it would still need action-count ownership and the shared admission
monitor (`:174–177,278–280,376–379`), owner readiness, exact registry identity,
native action availability, worker acceptance and failure routing. Moving those
facts across another seam increases interface obligations; no present second
caller or alternate adapter earns that interface. No interface is proposed.

Existing `background/NotificationRefreshQueue.kt:15–52` already owns the real
state machine: capacity32, one retained original claim per key, in-flight
exclusion, real-progress gating, two actual native-attempt cap, and shutdown
retention. The coordinator owns native current/pending checks and original borrow
closure. The queue is deep relative to these responsibilities, not a pass-through.
Deletion test: removing it moves its map, synchronization and transition knowledge
into the coordinator without removing any native work. Locality gets worse.

Its Ticket has package-visible mutable bookkeeping (`:8–11`), but no caller
currently reads or mutates that bookkeeping outside the queue. This is a small
encapsulation opportunity, not evidence warranting a fresh lifecycle refactor.
Pure tests already cross its real interface (`NotificationRefreshQueueTest.kt:9–81`).
They do not establish actual Android tap/authentication behavior.

## Retained depth in the other changed paths

- `background/RequestActionFailurePolicy.kt:9–27` serves actual approval and
  denial callers (`ApplicationApprovalCoordinator.kt:315–325,398–404` and
  `DenialJob.kt:199–239`). Deleting it duplicates exception classification and
  obscures the stricter cleanup semantics. The adjacent five-input denial policy
  has one caller reading directly from its original cancelled job; another data
  carrier would rename rather than eliminate that knowledge.
- `crates/android-bindings/src/peer_removal.rs:12–58` offers one downward intent
  containing ID validation, exact current association resolution, durable revoke,
  intake cancellation and presentation pruning. `intake.rs:193` owns existing
  peer lifetime details. Splitting this transactional order among more modules
  would make the caller interface shallower. No generic removal framework needed.
- `crates/windows-service-host/src/startup_phase.rs:19–43` owns original-budget
  polling/cancellation while `ffi/process_observer.rs:225–386` keeps Windows
  state/self-PID/control interpretation and numeric diagnostics with its adapter.
  The test seam is private. A public generic retry abstraction would expose more
  behavior and invite mutation retries that the current interface excludes.
- `ui/src/useConnectionDisplay.ts:9–22` serves three real display callers:
  `CollectionPanels.tsx:14`, `StatusPanels.tsx:28`, `RequestPanel.tsx:50`.
  Deletion repeats timer/identity/unknown invalidation behavior. Do not move this
  display state into native Request/Decision authorization snapshots.
- Outcome tags appear in both `phone-request-core/src/outbox.rs:122–146` and
  `activity-journal/src/outcome_history.rs:350–374`. Those encode distinct durable
  formats; outbox tags additionally feed delivery IDs (`outbox.rs:79`). The same
  enum and explicit tests preserve semantics. A shared public storage-codec
  module would couple future format evolution without adding current leverage.
  Legacy tag4 must remain unknown completion; new tags5/6/7 remain exact PC results.

## Non-negotiable invariants and validation scope

- Refresh never repeats an action, authentication or consumed PendingIntent.
- Only the original still-current pending handle can yield fresh presentation;
  shared admission prevents invalidating an already admitted action.
- Busy never self-polls; actual attempts are capped; waiting for cleanup is not
  an attempt. Stop retains in-flight ownership through actual native return.
- Request-local rejection does not soften native cleanup uncertainty or discard
  original denial scope/approval cursor ownership.
- Exact association generation/durable removal precede downward cancellation;
  shared device keys and unrelated PCs remain owned.
- Startup retains the original30-second budget, exact self-PID and no-controls
  prerequisite, strict later rechecks and pre-publication/final fences.
- Display grace and authenticated terminal history remain separate from approval
  authority and actual Windows outcome generation.

The source review and pure test-source inspection justify architecture selection,
not passed CI, physical incident reproduction, new phone authentication or native
UAC acceptance. ROOT continues exact-commit CI and release review independently.

SUPERLOOPY_EVIDENCE: .superloopy/evidence/20260920-boot-and-outcomes/architecture.md
