# Native pairing lab presentation readiness — 2026-09-19

Status: implementation and static inspection complete; ROOT CI validation pending.
No build, tests, formatter, lint, executable checks or device QA were run by this worker.

## Observed source/log evidence

- Read-only `gh run view 35409994348 --log-failed` shows `Native pairing e2e failed at qr-pixels` at 2026-09-19T00:49:41Z, commit `880792fd2e5206f84e400dbadb2811b0b25d6400`.
- Read-only `gh run view 35386639737 --log-failed` shows the same stage failure at 2026-09-18T19:45:30Z, commit `fd0695e9e25df05f0cc319010a30e85aa21d3caa`.
- The filtered logs establish the failed stage, not the exact QR count or a proven paint-race cause. Existing `expected_exactly_one_qr` collapsed zero and multiple grids into one reason.
- `tools/ci-windows-operator/ProtectedUi.cs`: `DismissIntroduction` only waits for control 1003 destruction. `CaptureQr` then captured immediately. A destroyed introduction control does not establish completed QR painting.
- The former `ReadComparison` accepted visible control 1001 as readiness and performed OCR once. Visible control creation likewise does not establish completed code painting.
- `tools/windows-full-pairing-lab.mjs` formerly grouped pixel read, phone confirmation, PC confirmation and signed acceptance under one `comparison` stage. Its catch preserved classified fixture diagnostics but lost `PrivateChild.failure.reason` for timeouts, stream errors and child exits. These omissions explain why the failure report alone could not resolve the comparison interruption's cause.

## Changes and bounds

- `tools/ci-phone-fixture/src/pixels.rs` now distinguishes no grid (`qr_not_ready`) from multiple grids (`expected_exactly_one_qr`). One grid must still decode and pass `PairingInvitation::from_qr_text`. Invalid PNG, malformed/undecodable QR, multiple grids and protocol failures remain terminal.
- The phone accepts at most 25 pixel captures before enrollment. It fixes a ten-second deadline at the first pixel frame; the prior bounded initial-command wait remains separate. No retry can regenerate identity keys, restart an enrollment attempt, or switch to a raw-text invitation after pixel capture.
- `Program.cs`/`PipeBridge.cs` admit repeat `capture_qr` only in the pre-comparison phase, with a 25-capture ceiling. The operator fixes a ten-second deadline after the one-use initial consent/introduction. Each capture still rechecks the current protected desktop, renderer identity/start/session, installed service hash and screen geometry. Initial consent is never repeated.
- `ci-presentation-readiness.mjs` spaces zero-grid retries by 200 ms and applies its own attempt/time limits. The first capture includes consent; its duration does not consume an arbitrary ten-second consent budget. The readiness budget does not shorten the subsequent authenticated enrollment exchange. Pixels remain process-pipe-only and the JS reference is cleared in `finally`.
- `ProtectedUi.ReadStableComparison` requires two consecutive independently captured matching code reads separated by 150 ms. Only six explicit OCR paint/glyph failures retry, for a fixed ten-second budget. Identity/desktop/geometry/font failures are immediate; any change between successfully decoded codes is terminal even across an intervening unreadable frame. The final confirmation continues to capture/check the expected actual code and the unchanged button before clicking once.
- Failure proof now distinguishes `comparison-read`, `comparison-phone-confirm`, `comparison-pc-confirm`, `comparison-signed-acceptance`; includes QR capture count; and records payload-free private child snapshots (closed, numeric exit, signaled flag, fixed failure reason, queue count, waiting flag). No raw exception message, stream text, QR data or comparison digits enter evidence.

## Added negative controls / ROOT verification

- `node --test tools/ci-private-child.test.mjs tools/ci-fixture-diagnostics.test.mjs`
  - Retry only exact zero-grid response; do not retry thrown fixture failure/invalid response.
  - Independent attempt and monotonic time caps; do not apply paint budget to authentication duration.
  - Snapshot preserves timeout/invalid-response classification without retained payload.
- `cargo test --locked -p ci-phone-fixture`
  - Blank PNG yields only `qr_not_ready`; one-grid boundary accepted; multiple grids terminal; existing malformed input tests retained.
- Existing hosted `tools/ci-windows-operator/build.ps1` + native digit canary (already invoked by Windows UAC lab workflow):
  - Missing/partial paint followed by two stable reads.
  - Renderer/desktop/DPI/region/font failures are not retried.
  - Missing paint exhausts one deadline; a different valid code fails even after a null frame.
- Exact-commit `windows-uac-lab.yml` must pass the real protected-pixel QR/enrollment/denial flow. ROOT should inspect `pairing-e2e-proof.json` for actual retry count and, if failed, the new precise stage/process records. Rust fmt/Clippy/Analyzer remain ROOT/CI gates.

## Limitations

The race is source-supported, not reproduced or proven by this worker's tests. Historical comparison failure cause remains undetermined until new diagnostics or its retained artifact is examined. Zero-grid retries deliberately cannot hide malformed/multiple QR frames or authentication failures. Pure synthetic controls are not native/device evidence. Hardware Android attestation, real phone authentication and the user's actual UAC acceptance remain user-test items.

## Added native lease-lifetime proof (ROOT follow-up)

`tools/ci-phone-fixture/src/session.rs` now deliberately holds the actual native consent for 115 seconds after verifying Opened, beyond its bounded original 110-second lease. It continuously drives the cancellation-safe socket and independently verifies each Renewed signature, exact prior binding/issuance chain, persistent request ID/content digest/PC/epoch/session, changed nonce, increased expiry/issuance, canonical metadata and clock freshness. Any Resolved event during this hold is a terminal failure, as is absent renewal or a hold exceeding150 seconds. It signs only the latest renewed binding and requires the exact corresponding signed Denied resolution.

`lease_renewed` emits only public IDs/digest plus measured hold milliseconds and renewal count after the full hold. The root harness now requires that state, 115000–150000 measured milliseconds and at least one verified renewal before denial; records nativeHoldMillis/leaseRenewals and a distinct request-native-lease-hold stage. Phone response wait is150 seconds solely to accommodate the115-second intentional hold. Its previous300-second whole-run cap becomes420 seconds (+115 hold +5 scheduling margin). Operator/authentication deadlines are unchanged; operator already finishes before the request hold. Existing GitHub job budget needs no extension. This new real-native proof is pending exact-commit CI and is not reported as already passed.
