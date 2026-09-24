# Measured signed denial latency

Run35581683195 attempt2, source816facce4b780e31868e6590344637f8bcbd2a9b,
completed success. Exact artifact10631222508, created2026-09-21T09:36:36Z.
Original proof:latency-attempt-2/exact/pairing-e2e-proof.json.
ROOT gh run watch exit0; proof passed=true, wirePassed=true,
nativeWindowsDenied=true. No real phone or hardware-authentication claim.

- Software signing start -> same-request verified PC resolution:271329us =271.329ms.
- Queue start -> same-request verified PC resolution:271275us =271.275ms.
- Sample count1; decision deny; same-process monotonic clock.
- Includes software signing, local relay transport, Windows decision and signed
  reply validation. Excludes Android runtime, biometric prompt, mobile network,
  tap-to-render. Deliberate renewal hold115006ms is excluded.
- Actual original Windows request ERROR_CANCELLED and target-not-executed are
  separate required native checks, not inferred from the local phone choice.

Earlier attempt1 failed enrollment close_failed before measurement; it is not a
latency sample. `gh run download --name` picked the older same-name artifact
even after rerun success. Root selected exact artifactID10631222508 via authenticated
GitHub CLI and verified its source+passed flags. The first ambiguous download
is preserved under latency-attempt-2 root; ONLY exact/ is this successful sample.

Interpretation: this sample exceeds the approximate100ms immediate-response
heuristic but stays below1s thought-flow heuristic (NN/g reference in research
doc). It supports immediate local selection feedback plus retained confirmed
result, without imposing an artificial loading delay. It cannot establish real
Android p50/p95, approval latency or a universal spinner threshold. Slow/offline
states still need actual-owner progress and honest result-unknown recovery.

Research design stays in docs/decision-feedback-research.md. UI implementation
needs native request-to-receipt correlation; no last-history-row inference.
