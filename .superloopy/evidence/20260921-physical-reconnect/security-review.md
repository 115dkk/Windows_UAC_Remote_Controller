# Physical metrics and default-network recovery: static security review

Date: 2026-09-21. Scope: working-tree delta against `ddadc7d`, reviewed by the
independent `physical_security_review` child. No product edits, build, tests,
lint, formatting, executable checks, phone actions or other validation were run
by this reviewer. ROOT/CI owns all execution and physical evidence.

## Final static verdict

No remaining new high/medium security or correctness issue was found in the
instrumentation/network delta after the metrics owner's M1 fix. The pre-existing
native presentation race M3 below remains a required separate UI follow-up.
Network recovery preserves the reviewed
authorization boundary. Metrics use the genuine native authentication callback
and authenticated request-terminal observations, with attempt-token isolation and
bounded ambiguity exclusion. M2 remains the explicitly accepted observational
scope limitation, not evidence of a winning phone. ROOT/CI and controlled
physical-device gates remain required; this is not a passing execution gate.

## Findings sent to ROOT

### M1 — stale callbacks can change a replacement sample (medium)

`NativeDecisionMeasurements.accepted` replaces `entries[locator]` for an opposite
choice or retry. `NativeRequestCoordinator.approvalResult` and denial callbacks
subsequently call `decisionPrepared`, `decisionLocalStatus`, and `phase` with the
locator only. An earlier approval cancellation delivered after an accepted
same-request denial can stop the new denial sample as `local_unconfirmed`;
subsequent legitimate progress is ignored because `localStopped` is set. The
approval/denial drain correctly prevents authorization races, but it does not
make these observational callbacks belong to the same local attempt.

Replacement also removes the previous same-generation sample, so
`matches.singleOrNull()` cannot detect the historical ambiguity suggested by its
comment. A late result for the first attempt observed after the retry's start
can appear to belong to the retry.

Requested remedy: an observation-only per-attempt token captured by callbacks;
ignore stale-token progress/preparation/local cancellation. Preserve bounded
same-request attempt ambiguity, and do not assign post-authentication latency to
an ambiguous winner. This must not alter native action admission, cleanup or
approval/denial authorization. ROOT has been asked to assign the metrics owner.

Final disposition: fixed by the assigned metrics owner and statically re-reviewed.
`NativeDecisionObservation` is captured by each admitted action. Preparation,
local status and metric progress require both locator and exact token identity.
Generic registry phase changes no longer update metrics; retained approval
submissions carry their own `deliveryObservation`, including delivery-driver
progress. The token is not consulted by native authorization.

A separate 64-attempt/300-second history survives visible-locator replacement.
Shared receipt identities suppress eligibility; history overflow conservatively
suppresses all timing for 300 seconds, so eviction cannot establish false
uniqueness. Ambiguous outcomes remain visible as PC request outcomes.
`timingAvailable` / `timing_eligible` excludes ambiguous, missing-authentication
and opposite-outcome approval samples. Unique prepared denial outcomes may
provide action-to-result timing without an authentication interval. DTO and
diagnostic validation enforce these distinctions.

New synthetic tests cover stale approval cancellation/preparation/progress after
denial; same-ID retry and different-locator overlap; unrelated requests; history
overflow and expiry recovery; missing-authentication and opposite outcomes; and
late PC results. Their source was reviewed, not executed by this child.

### M2 — request completion does not identify the winning phone (scope limitation)

`crates/service-protocol/src/message.rs::PcEvent::Resolved` carries binding,
original issuance and outcome, but no winning device or decision. In
`crates/windows-service-host/src/peer_runtime.rs::publish_event`, that signed
resolution is queued to every current clock-served peer. Consequently an exact
receipt is strong evidence of the same request's PC outcome, but cannot establish
that this phone's locally authenticated decision caused it. A second phone can
win while this phone authenticates or even before it signs; a local auth-none
sample may legitimately receive `approved`.

This is not a new authorization bypass. The existing global request slot retains
one winner. It is an evidence/UI boundary: use request-terminal wording, never
infer “this phone applied its approval” from these fields. A controlled physical
trial can report the interval from this phone's actual authentication callback
to receipt of the same request's PC result, with the single-actor conditions
recorded. General winner-specific UI or causal measurements require a signed
winner/decision acknowledgement and the corresponding protocol review. ROOT was
notified before publication or UI implementation.

ROOT disposition: retain the observational scope; no winner-protocol expansion
is authorized for this slice. The feedback design distinguishes local selection
from the PC's request result. For a physical benchmark ROOT requires a controlled
single-phone canary, actual OS-authentication/signature observations, PC
`PhoneDecisionVerified` plus `WindowsApplied`, and the fixed process result.
Ambiguous, missing-authentication and opposite-outcome samples are excluded.

### M3 — native request phase still has pre-existing locator-only callback ownership

ROOT correctly identified that `NativeRequestRegistry.phase` token-fences only
`decisions.progress`; it still mutates the actual `NativeRequestEntry.phase` by
locator. An old approval cancellation callback can therefore set the native
request presentation back to `PENDING` after a denial has been admitted, even
though the new denial's metric/decision-feedback sample remains unchanged.

This native phase mutation is unchanged from `ddadc7d`, not introduced by the
measurement tokens. It cannot by itself grant a second approval: the approval
coordinator separately requires `!denialBlocked(selection)`, and the exact-request
denial blocker remains owned by `DenialJobs` until its native drain/cleanup.
Authoritative Rust request/signature/denial checks also remain unchanged.
Nevertheless, the native request's displayed state can be confusing; this is a
real presentation correctness issue, not a claim that locator-only phase
ownership is adequate.

Disposition communicated to ROOT: permit the network/metric-only CI candidate
and physical instrumentation benchmark now. Before the separate new feedback UI
ships, implement and test bounded native action-generation ownership for phase
callbacks, distinct from optional metric/diagnostic state. The new phase owner
must derive from actual native action admission, travel with that action's
callbacks and retained submission, reject superseded generations, and preserve
all existing denial drain and authoritative request checks. Do not make
`timingAvailable`, metric entry presence, or the observation-only token an
authorization owner. Required cases include approval-to-denial with late
approval cancellation/preparation, rejected/busy admission, request replacement,
and terminal cleanup. This reviewer made no product edit for M3.

## Positive source observations

- `PendingOutcome::delivery_id_for` reuses the canonical existing SHA-256
  construction over PC, epoch, session ID, logon ID, request ID, nonce, content
  digest, expiry, original issuance and outcome tag. It neither enqueues an
  outcome nor creates an action capability. Wrong issuance/reissued requests do
  not share identity.
- Native receipts come from owner-committed pending outcomes, not a renderer,
  last history row, disappeared request, local button choice or socket write.
  `CompletedByPc` and local expiry retain non-approval meanings. Duplicate
  retained receipts keep the first observed timestamp; receipt/visible-sample
  storage is bounded to 32, historical attempts to 64, and measurements to
  300 seconds.
- `NativeApprovalOperation.authenticated` records its time only after the
  actual framework callback passes original host, CryptoObject object identity,
  policy and cancellation checks. It does not accept a UI-supplied success flag.
  Missing authentication observations stay absent. Biometric failure and local
  cancellation are not PC denial/application.
- Action/authentication/signature observations use Android
  `SystemClock.elapsedRealtimeNanos`. The outcome side calls
  `AndroidNativePlatform.clock`, whose native environment observation supplies
  the same clock family; Rust additionally checks boot/shape and the existing
  floor. These measurements do not subtract a PC timestamp or use ping.
- The metric sink is closed-token, body-free and arithmetic/size checked.
  Emit failure is caught; metric fields never enter signing, peer trust,
  decision admission or request-expiry gates.
- `network_changed` holds the same nonreentrant owner admission as carrier
  attachment. It cancels the old network token, clears only dial backoff and
  retires old carriers; it does not replace associations/keys, restart the owner,
  mutate bindings/deadlines, reenroll or resubmit a user decision.
- Dial completion is generation-checked. Old rendezvous jobs are cancelled;
  `attach_network_stream` rechecks cancellation inside admission, and parked
  attaches recheck the retired peer token. Fresh carriers still use the original
  leased identity, TLS pins, signed request verification and real readiness.
- Android observes the OS default network, including VPN. No `bindProcessToNetwork`,
  explicit Wi-Fi socket factory, hidden underlying-network API or routing bypass
  was added. Delayed old-network loss/capability callbacks cannot replace the
  new default. Public transport-mask changes are coalesced; unrelated capability
  jitter does not force reconnect. Missing VPN bearer reports remain a detection
  limit, with existing connection maintenance still present.
- Pre-unlock callbacks only retain in-memory default-network state; flushing
  requires the existing owner/credential-storage readiness gate. Callback
  registration is service-lifetime scoped and unregistered at destruction.
- Actor queue/admission pressure has four prompt retries before the existing
  15-second maintenance fallback. No native network event opens a biometric UI
  or invokes approval/denial. A public relay remains a separate deployment need:
  private LAN reachability is not converted to mobile-WAN reachability by retry.

## Symbolic source bindings

None of the delta's product files intersects the current manifest's 12
`sourceBindings`. Therefore this delta requires no automatic hash rebinding.
The exact currently hash-bound paths are:

1. `crates/secure-channel/src/identity.rs`
2. `crates/secure-channel/src/config.rs`
3. `crates/secure-channel/src/channel.rs`
4. `crates/approval-protocol/src/lib.rs`
5. `crates/approval-core/src/lib.rs`
6. `crates/service-protocol/src/message.rs`
7. `crates/service-protocol/src/codec.rs`
8. `crates/windows-service-host/src/peer_runtime.rs`
9. `crates/windows-prompt-probe/src/ffi/watch.rs`
10. `crates/phone-request-core/src/inbox.rs`
11. `crates/notification-policy/src/lifecycle.rs`
12. `crates/windows-service-host/src/peer_runtime/prompt.rs`

The static alignment remains the documented intact-OS trusted per-use auth,
peer pinning, full signed request binding, immutable request origin, global
single-consumption and revision/deadline assumptions. No theorem, canary,
expected result or authentication premise was changed. Carrier scheduling,
Android callback ownership, physical authentication, timing, result attribution
and Windows application are outside the symbolic proof. ROOT must still run the
current-source normal prover gate and required negative controls in CI.

## Physical evidence limits and required follow-up

ROOT's first reported physical trial ended unconfirmed after about 122 seconds,
without `PhoneDecisionVerified` or `WindowsApplied`; that is not an authentication
latency sample. Ping, TCP reachability, a READY Android owner and a running
Windows service do not replace an actual phone-authenticated decision trial.

`tools/measure-physical-approval.ps1` explicitly labels its whole-request timing
as including human reaction and sets isolated authentication measured to false.
Its PC diagnostic counters filter by service PID and time, not a request ID;
they are corroboration only under a controlled trial, not causal proof if
concurrent requests exist. The new phone instrumentation must be installed with
the existing signer and paired with an actual user biometric/PC application
observation. No privilege-policy weakening or retry around the previously denied
native inspection is justified. Mobile-WAN proof additionally requires an
authorized reachable endpoint and actual network-switch trial.
