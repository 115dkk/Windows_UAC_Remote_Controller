# Android default-network recovery implementation

Status: implementation and static source review only. This child did not run build, tests, lint, formatting, executables, device commands, or network measurements. ROOT/CI owns validation.

## Scope and invariants

- `ControllerForegroundService` registers an Android default-network callback on main and unregisters it on destruction. It observes OS-selected routing (including VPN); it does not select Wi-Fi, bind a socket to a network, or bypass routing/firewall policy.
- Network identities exist only in process memory. Service dumps expose callback-registration state and a saturating reset-request count, not handles, IPs, SSIDs, keys, or credentials. They appear in a separate closed `UAC_NETWORK_V1 callback_registered=... reset_requests=...` line after `UAC_LIFECYCLE_END_V1`; the existing strict lifecycle V1 field block is unchanged.
- `DefaultNetworkPolicy` ignores duplicate available and delayed loss callbacks for replaced defaults; 250 ms coalescing emits the final observed default. A genuine lost-and-returned same identity still retires the disrupted carrier. A healthy initial default prompts maintenance without retirement.
- Public transport-type changes from `onCapabilitiesChanged` detect a stable VPN default switching its reported Wi-Fi/mobile bearer. First capabilities establish a baseline; duplicate masks and stale-identity callbacks do not reset. Signal, bandwidth, meteredness, validation and other capability changes are excluded from comparison. A masked bearer transition that Android/VPN never reports is not detected by this mechanism; underlying private network identities are not obtained with hidden APIs.
- Pre-unlock events only update memory. Service maintenance requires current foreground-service generation and READY policy owner, preserving existing CE/key startup boundaries.
- `ApplicationPolicyActor` serializes the fixed native lifecycle signal on its existing worker. Latest event wins; Busy/queue pressure gets at most four 250 ms retries before returning to the existing 15 s maintenance tick.
- `MobileController.network_changed(available: bool)` takes existing owner admission, cancels old rendezvous operations, clears only dial backoff state, and retires old peer carriers. No association/key mutation, action invocation, request deadline extension, or replay mechanism is introduced.
- Dial completions carry native network generation, so stale completion cannot clear a new dial's in-flight state or reintroduce old backoff.
- Failed-dial backoff starts at actual native completion time, rather than being deferred until the next maintenance tick consumes the completion.
- Network stream attachment checks cancellation *after* acquiring the same owner admission used for retirement. It cannot pass an old-generation check then attach after replacement. Cancelled prepared attachments are discarded before constructing the authenticated socket.
- No-default state suppresses periodic dials; return of a default resets backoff promptly. Public/WAN reachability still depends on the registered endpoint's actual routability. A private LAN address remains unavailable over ordinary mobile data without an external deployment/route.

## Changed files

- `crates/android-bindings/src/connectivity.rs`: generation/cancellation, availability, bounded native reset, three new Rust test cases.
- `crates/android-bindings/src/intake.rs`: internal cancellation-fenced attachment and cancelled prepared-attach guard.
- `src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/background/ControllerForegroundService.kt`: service-lifetime default-network callbacks and diagnostics.
- `src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/background/ApplicationPolicyActor.kt`: coalesced worker admission and bounded retry.
- `src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/background/DefaultNetworkPolicy.kt` and matching JUnit test: pure identity/transport policy; eleven test cases.

## Public Android API source check (2026-09-21)

[Android Developers: Read network state](https://developer.android.com/develop/connectivity/network-ops/reading-network-state) documents VPN transports changing from cellular to Wi-Fi while VPN transport remains, and recommends consuming callback capabilities instead of synchronous lookups inside `onAvailable`. [NetworkCapabilities reference](https://developer.android.com/reference/android/net/NetworkCapabilities#hasTransport(int)) supplies the public `hasTransport(int)` API. This implementation compares only these bits; newer USB/Thread/satellite constants are platform-version guarded. The public reference provides no underlying-network-identity getter used here.

## Required integration/validation

ROOT adds `android.permission.ACCESS_NETWORK_STATE`. Metrics lane owns the shared ABI increment for the new `networkChanged(Boolean)` export. No new `lib.rs` fields or export records are required from this lane.

CI must run Rust fmt/Clippy/test and Android unit/package gates. New Rust tests exercise real loopback rendezvous cancellation without a READY response, no connection for pre-cancelled queued dials, and stale-success/failure completion fencing. Existing socket/request-source and native transport tests remain required for authorization regressions.

ROOT should use the physical phone for callback registration/lifecycle, duplicate foreground/start behavior, default-network loss/return and authenticated reconnection observations. Measure request/decision/PC application separately; none of these source changes or policy tests constitute phone authentication, application latency, or mobile-WAN proof.

## Rust Analyzer Send-bound correction

ROOT reported exact commit `3c3d4e6`, Quality run `35605469630`, Linux job `106351364926`: Analyzer `RustcHardError E0277`, `Arguments<'<erased>>: Sync is not satisfied`, at `dial_jobs.spawn(run_dial(...))`. ROOT also reported Rust tests, Clippy and the Android build passed for that commit. This child did not execute validation.

The previous new `run_dial` implementation nested a borrowing async block (including synchronous stream attachment) inside `tokio::select!`. There are no application `fmt::Arguments` values in its inputs. The installed locked Tokio select macro creates a borrowing `poll_fn` closure and a formatted panic fallback; the reported type is therefore consistent with Analyzer's coroutine/capture inference through that expansion, not evidence of a compiler-confirmed non-Send application value. The precise Analyzer internal capture cause remains an inference until the corrected exact-commit gate runs.

The patch removes that new nested select expansion. It uses the installed, locked `tokio-util 0.7.19` `CancellationToken::run_until_cancelled_owned` around only the rendezvous future and performs synchronous admission after the await. `run_dial` now returns `impl Future<Output = DialCompletion> + Send`, making Send an explicit production signature requirement (the same pattern already used by intake `wait_peer`), without suppressions, unsafe traits, changed Analyzer settings or weakened validation.

The cancellation combinator may favor completion if completion and cancellation coincide. The existing exact-token check after owner admission remains decisive: a carrier returned in that race cannot attach after its network generation was cancelled. Pre-cancelled network tokens never poll the dial future, and cancellation of a pending wait drops its socket. Existing new cancellation/backoff tests and the unchanged strict Analyzer gate remain required on ROOT's next CI commit.
