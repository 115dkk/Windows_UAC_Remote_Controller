# Instrumentation CI — 3c3d4e60ba41bf4feacce3a7d8d13b0f8435a21e

ROOT dispatched normal workflows against this exact branch head and verified
the head SHA. Results below are an intermediate observation, not final gates.

- Android arm64 APK and Kotlin unit tests35605473433: success.
- Minified release startup35605477220: current and alpha4 negative-control
  jobs both success.
- Windows package35605485491: success.
- UI gallery35605493687: success; no new rendered-surface claim reviewed here.
- Android notification renderer35605497748: success.
- Localization35605501649 and attestation interoperability35605505145: success.
- Quality35605469630: failed, gh run watch --exit-status returned1.
  Both Linux106351364926 and Windows106351364989 report the same actual Rust
  Analyzer E0277 at intake.rs zero-based879..883, dial_jobs.spawn(run_dial(...)):
  Arguments is not Sync. Rust compiler/tests and Android core Clippy passed;
  analyzer diagnostic remains a real failed gate. Tamarin and Cargo Deny passed.
- Windows UAC lab35605489096 and Android lifecycle35605481160 were still running
  at this observation; their final results must be checked separately.

The duplicate PR Android package35605313649 failed resolving Maven Central
dependencies with HTTP429; the exact manual package subsequently passed. No
mirror/IP bypass was used. Superseded duplicate PR runs were cancelled to avoid
additional parallel build traffic, not counted as successful checks.

The follow-up patch structurally separates cancellable rendezvous await from
synchronous attachment and gives run_dial an explicit Send future contract.
It does not suppress analyzer diagnostics. ROOT will verify a new exact commit.
