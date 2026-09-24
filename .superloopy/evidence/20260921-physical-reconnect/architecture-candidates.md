<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Native connection/measurement architecture candidates

Date: 2026-09-21. Reviewed delta: `ddadc7d..a1c5ae8d925486d13964cb3b38966d4979f39324`, branch `codex/decision-feedback-research`.

## Recommendation and selection

**Strong no-refactor recommendation for this native delivery slice.** No worthwhile deepening candidate survived the deletion test. ROOT subsequently approved no product refactor in `architecture-approval.md`; the final scoped disposition is `architecture-result.md`. This does not complete the larger reconnect/physical-latency/conditional-feedback objective.

HTML report: `C:/Users/32170336/AppData/Local/Temp/architecture-review-20260921-230343.html`. It contains current/retained visualizations, including the intentional observation/action ownership separation.

Read the complete `improve-codebase-architecture` skill, LANGUAGE.md and HTML-REPORT.md; read CONTEXT.md and ADRs 0014, 0015, 0027 and 0031 before exploration. One bounded read-only explorer covered measurement/phase ownership. This reviewer covered network recovery and the one-off workflow/helpers. Current source and `security-review.md` / `security-followup.md` inform the findings; historical glossary/ADR implementation-status statements are not current executable evidence.

## Why retaining the current modules has more leverage

1. **Connection recovery has separate, useful seams.** `src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/background/DefaultNetworkPolicy.kt:6` owns stale identity/loss/capability coalescing behind a small interface. The Android adapter registers and retires callbacks and respects unlock readiness (`ControllerForegroundService.kt:249`, `:272`, `:284`). `ApplicationPolicyActor.kt:318` keeps bounded worker admission/retry local. Rust `crates/android-bindings/src/connectivity.rs:154` cancels a network generation, clears dial backoff and retires associated carriers under existing admission; `:282` separates asynchronous rendezvous from synchronous admitted attachment. `crates/android-bindings/src/intake.rs:498` checks the exact cancellation token after owner admission. Deleting the policy module spreads ordering knowledge into three Android callbacks. Combining OS observation with Rust recovery makes the interface carry platform, scheduler and native owner knowledge without concentrating the implementation. The small attachment adapters share one implementation rather than duplicate the critical check.

2. **Decision observation is already deep; phase ownership must remain independent.** `NativeDecisionMeasurements.kt:31` concentrates retention and attempt identity; `:79` concentrates exact receipt matching, ambiguity exclusion and timing eligibility; `:116` presents the bounded projection. `NativeActionPhaseOwner.kt:18` independently owns current-generation admission/retirement/replacement. `NativeRequestCoordinator.kt:196` and `:232` install generations only after actual native admission; later callback/delivery paths carry those generations (`:322`, `:347`). `NativeRequestRegistry.kt:294` checks current generation before phase mutation; retained submissions remain separate from diagnostics. Merging the modules would let optional observation lifetime influence native phase ownership. Deleting the measurement module spreads its correlation rules across callbacks. Existing `PendingOutcome::delivery_id_for` (`crates/phone-request-core/src/outbox.rs:46`) keeps canonical receipt identity local; projection uses it rather than duplicating the digest.

3. **The one-off measurement lane is not a general release abstraction.** `.github/workflows/android-physical-measurement.yml:21` restricts branch/actor and exact source; `:61` requires the persistent signer; `:94` binds passive artifact inspection and checksums. Tagged publication has additional policies, including a separate existing prerelease signer mode. Factoring the lanes now adds policy switches, not useful depth. The fixed UAC trial (`tools/measure-physical-approval.ps1:15`) and current-process Android metric reader (`tools/read-physical-decision-metrics.ps1:11`) have different clock/evidence interfaces; combining scripts cannot establish a winning phone or request-specific cross-device causality.

Paths with only Kotlin basenames above are under `src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/background/`.

## Considered but not promoted

- Retained delivery, generation and observation are three parallel fields in `NativeRequestRegistry.kt:112`–`:114`, transferred at `:179`–`:182`, retained at `:339`, and cleared in the same module at `:555`. A small private bundle could reduce repeated assignments, but state already has locality and this does not solve the actual main/worker scheduling test seam. No candidate is proposed solely to move these fields.
- Extracting a pure network retry helper from `ApplicationPolicyActor` would not exercise OS callback registration, worker admission or unlock readiness. Keep those integration tests as ROOT/CI evidence work rather than presenting pure tests as native validation.
- No new generic adapter interface: a second real implementation needing substitution has not been identified for the proposed extra seams.

## Invariants and remaining evidence

- Preserve ADR0014 denial scope, native drain and cleanup; ADR0015 one native intake owner and revocable Request presentation; ADR0027/0031 configured relay semantics and physical reachability limits. No ADR conflict/reopening, new domain term or new interface is proposed.
- Preserve intact-OS threat scope, Secure Desktop/UAC, pinned transport, request/lease checks, per-use phone authentication, local-choice versus PC-outcome distinction, pre-unlock constraints, all bounds and fail-closed behavior.
- Existing source tests cover default-network identity/transport changes (`DefaultNetworkPolicyTest.kt:8`–`:111`), old-generation completion and cancelled rendezvous (`connectivity.rs:428`–`:498`), bounded measurements and phase-generation transitions. They were inspected, not executed. Pure tests do not prove Android scheduler integration, real phone authentication, reachability or Windows application.
- Current `a1c5ae8` source uses `async fn run_dial` and relies on the production `JoinSet::spawn` Send requirement (`connectivity.rs:282`–`:289`); `security-followup.md`'s explicit `impl Future + Send` wording describes an earlier source form, not this exact form.
- Exact CI and released artifacts remain ROOT responsibilities. The installed physical instrumentation APK is the earlier signed `c48598a` candidate per ROOT assignment, not proof of this HEAD or a valid authentication sample.
- ROOT subsequently supplied `physical-trial-02.md`: on that installed `c48598a` candidate, actual Wi-Fi disable/restore kept the native owner READY, incremented default-network reset requests 0→1→2, restored Wi-Fi and re-established one phone→PC TCP connection. This is physical callback/TCP reconnection evidence, not native TLS/application readiness or UAC authentication. The canary remained unconfirmed with no decision samples; further canaries await user readiness. ROOT also reports exact `a1c5ae8` Android build/JVM gates passed while full Quality remains running; this review does not independently certify those execution gates.
- A valid controlled physical sample is still absent. Feedback UI remains DESIGN ONLY. Same-request PC receipts do not identify the winning phone. No external relay deployment or authentication requirement expansion belongs to this review.

Review actions: static source/metadata reads and report writes only; no builds, tests, lint, formatter, executable/device QA, private state/key/journal reads, commits or pushes. Existing untracked `.claude/` and `.codex-remote-attachments/` were left unchanged.

SUPERLOOPY_EVIDENCE .superloopy/evidence/20260921-physical-reconnect/architecture-candidates.md
