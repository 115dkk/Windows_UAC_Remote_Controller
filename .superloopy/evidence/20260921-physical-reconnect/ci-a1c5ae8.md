# Exact product-source CI and native artifact review

Product SHA: a1c5ae8d925486d13964cb3b38966d4979f39324.
Immutable intended prerelease tag: v1.2.0-alpha.2.

ROOT verified completed success for all original exact-head dispatches:

| Gate | Run |
| --- | --- |
| Quality (both hosts, actual Rust Analyzer/canaries, Android Clippy, Tamarin, Cargo Deny) | 35608485997 |
| Android package and Kotlin unit tests | 35608569332 |
| Android minified release startup and negative control | 35608569559 |
| Android product lifecycle | 35608569094 |
| Windows package | 35608569243 |
| Windows UAC lab | 35608569404 |
| UI gallery | 35608569247 |
| Android notification renderer | 35608569337 |
| Localization | 35608569103 |
| Attestation interoperability | 35608569114 |

Quality's native gh run watch --compact --exit-status completed with exit0.
The previous Analyzer E0277 and subsequent manual_async_fn Clippy failure are
resolved in this source; no warning/error suppression was added.

ROOT downloaded minified-current artifact10643927179. Its product-commit.txt and
result.json identify this exact SHA; release=true, minified=true, passed=true,
physicalDeviceVerified=false, authenticationVerified=false, pairedPcCount0.
Owner dump is READY with network callback_registered=true. ROOT visually
inspected pairing-actions.png: the existing QR/USB controls are separated,
readable and unobscured in this emulator rendering. This is an adjacent-regression
check, not a new feedback UI or a physical authentication screenshot.

ROOT downloaded lifecycle diagnostic artifact10643303609. prepare-dBKGfO/001.log
contains this SHA. run-V8hEil/result.json reports
REAL_PRODUCT_EMULATOR_LIFECYCLE_AND_FIRST_UNLOCK, passed=true,
firstUnlockVerified=true, cancelled=false, cleanupIncomplete=false.
Initial/start/first-unlock phases reach READY/ON; explicit stop reaches
CLOSED/OFF and subsequent stopped checks remain NONE/OFF.
physicalAuthenticationVerified=false and requestDeliveryVerified=false.
The preparation result's SOURCE_INPUTS_ONLY/passed=false is a source-preparation
record, not the later emulator-run verdict.

The CI Windows lab verifies the software-phone signed-denial/native request
path, not this user's phone authentication latency. Actual phone evidence and
its exact earlier candidate are separately recorded in physical-trial-02.md.

## Release attempt recovery

Release35610136489 attempt1 selected cancelled duplicate PR Quality35608489680
(created13:53:20Z) instead of successful exact-head Quality35608485997
(created13:53:18Z). Gate job106367008819 correctly failed on cancellation. ROOT
did not change the tag, assets, gate semantics or reported result. A fresh normal
Quality dispatch35610394592 targets the same immutable tag/SHA so the release
driver's latest-run selection can observe a current exact-source execution.

At this record's creation, that repeat and signed packaging are still running;
publication and its recovered final verdict must be recorded after completion.

Follow-up: tag Quality35610394592 completed success at the same product SHA;
its native watch exited0. Windows quality took17m49s, Linux9m38s; these are CI
build/check durations, not authentication latency. An attempted single-job
release rerun while Windows packaging remained active was refused as not yet
rerunnable. No rerun occurred from that attempt; ROOT waits for the workflow to
finish before using its normal failed-job rerun.

Final: after Windows packaging completed successfully, ROOT reran failed jobs
normally. Release35610136489 attempt2 and every job succeeded, native watch exit0.
Gate106377794746 selected current successful exact-source runs; publish106378032092
published the non-draft prerelease at2026-09-21T14:38:03Z. Tag/source unchanged.
