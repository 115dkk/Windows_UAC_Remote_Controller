# Finalization security review

Date: 2026-09-19. Reviewer: independent security_review child.
Baseline: `4a85f3b13c1d9717c264ce2358b0f8b550d5474d`.
Scope: working-tree finalization changes, including untracked USB/renewal files.
Method: static source/diff inspection only. No builds, tests, formatting, lint,
executable checks, device operations, or proof execution were run by this reviewer.

## Final integrated static disposition

Final reviewed implementation commit:
`a16c12c225494dc151a76fb3f998249af48c29c8`.

**PASS for the static security gate; proceed to the approved architecture phase
and ROOT-owned CI/native validation.** No confirmed critical/high security defect,
authorization bypass, stale-binding approval, suppression resurrection, or new
general-purpose privileged API was found in the integrated diff reviewed here.
No security fix remains open from this review. This verdict is source-level and
does not substitute for CI, hardware/device acceptance, or native USB compatibility.

The final pass inspected the completed phone renewal/migration and status evidence,
their implementation and regression sources, Android USB lifecycle, and the
completed native long-hold fixture. Formatter-only changes were included in the
reviewed commit; earlier line references below identify first-pass locations and
the final-pass references at the end identify the formatted integration state.

## Findings and action tracking

| Severity | Finding | Disposition |
| --- | --- | --- |
| Medium, availability/compatibility | Windows courier enumerates all installed WinUSB interfaces and refuses unless exactly one candidate exists. An unrelated WinUSB interface can prevent pairing. MTP-only driver configurations cannot be switched by this implementation. | Explicit constrained-support behavior, not an authorization bypass. Keep QR available and native device/driver compatibility unverified. `ffi/usb_bootstrap.rs:91,229`. |
| Medium, fixed before final verdict | Legacy inbox schemas did not retain renewable-lineage provenance. Retiring an old suppressed lease before receiving a renewal could otherwise lose suppression history. | CLOSED: implementation owner added source-epoch quarantine for all legacy source records, nonrenewable legacy rows, and a clock-first retired-suppression regression. Unknown Renewed events cannot escape quarantine; independently signed initial Opened events retain normal watermark/capacity/finite-quarantine checks as detailed in the post-review addendum. `phone-request-core/src/checkpoint_codec.rs:203,271`; `tests/renewal.rs:278`. |
| Low, evidence gap | New USB host/device I/O and the 115-second real-consent lab are not yet validated in this pass. Synthetic frame, protocol, and ownership tests cannot prove actual driver/permission behavior. | ROOT CI/native artifact review required; real phone authentication and actual user UAC acceptance remain deferred user tests. |

No reviewer code fix was necessary in the inspected slice. Active implementation
files were not modified. Review suggestions were sent to their owners rather than
overwriting concurrent work.

## Security invariants inspected

### USB is public bootstrap, not authority

- Rust frame codec accepts exact magic/version and 345/357-byte canonical bodies;
  it delegates semantic parsing to existing `PairingInvitation::from_wire`.
  `crates/windows-service-host/src/usb_bootstrap_frame.rs:6`.
- Android receives at most one bounded frame using a fixed 16 KiB packet buffer,
  366-byte application buffer, 30-second elapsed-time limit, and 200 ms poll.
  No URL/path/command or host-returned decision is parsed. `PairingUsbFrame.kt:5`
  and `PairingUsbSession.kt:93` under the native Android pairing package.
- The Android byte receiver calls the same `decoded` -> native actor invitation
  admission -> existing pairing ceremony path as the QR receiver. Comparison,
  attestation, pinned encrypted transport, and both confirmations remain required.
  `PairingScannerDialog.kt:208,222`.
- USB selection on Windows changes only private handoff variants and carrier
  choice. One-shot handoff admission requires the original bound starter and its
  pending identity; duplicate/crossed/helper-side invitation frames fail.
  `crates/windows-service-host/src/pairing_handoff.rs:745,766`.
- The service's original enrollment carrier and protected renderer still own
  comparison/commit authority. The courier neither confirms nor registers peers.
  `crates/windows-service-host/src/peer_runtime/pairing.rs:1164`.

### Privilege, sender, ownership and permissions

- Courier start and process entry both require the current primary token to meet
  the existing Starter profile: interactive nonzero session, medium integrity,
  not elevated, no enabled administrator group, no SYSTEM/AppContainer/UIAccess.
  `ffi/usb_bootstrap.rs:23,49,58`; `ffi/pairing_peer.rs:1218`.
- Executable is from the existing retained/pinned protected installation, not a
  WebView, USB or user-supplied path; child stdin carries only the public frame.
  Child watchdog bounds stdin/SetupAPI/control I/O to 50 seconds. WinUSB operations
  never run in the privileged service/renderer. Owned WinUSB interface closes
  before its file handle; SetupAPI snapshots and registry keys are released.
- Enumeration/buffer counts are fixed; no driver installation or rebinding, ADB,
  HID/input injection, or generic execution API was introduced. OUT-only bulk
  transfer requires accessory VID/PID, interface zero, and one IN/one OUT endpoint.
  `ffi/usb_bootstrap.rs:91,193,203,229`.
- Android permission callback only wakes the retained session. It ignores
  broadcast permission/accessory extras and rechecks actual `hasPermission` for
  the exact retained accessory. Random per-session action, package-scoped immutable
  one-shot intent, and receiver removal reduce callback confusion.
  `PairingUsbSession.kt:46,55,85`.
- Host continuity is checked before opening and delivering bytes. Closing marks
  the session stopped; ownership remains occupied until the worker releases the
  original descriptor, then dialog/actor/window release gates permit reuse.
  `PairingUsbSession.kt:147,159`; `PairingScannerDialog.kt:179,347`.
- Tauri USB commands require an empty entire IPC payload. Android entry additionally
  uses captured physical invocation origin and native foreground host admission.
  They accept no invitation, destination, peer key, approval or credential payload.
  `src-tauri/src/mobile.rs:55,199`; `src-tauri/src/commands.rs:204,367`.

### Native prompt and immutable bounded leases

- Heartbeat renewal witness is decided before census; due heartbeats trigger a
  fresh same-identity/content read, while content changes get a new target sequence.
  Lost/ambiguous/changed desktop targets withdraw the old tracked prompt.
  `crates/windows-prompt-probe/src/ffi/watch.rs:107,302,345`.
- Service renewal requires exact live target, no applying decision, an unexpired
  old lease, and a <=30-second remaining margin. New binding retains PC/epoch/
  session/request/content and frozen eligible devices, with a fresh nonce and
  later bounded expiry. Old/consumed/expired bindings cannot be revived.
  `crates/windows-service-host/src/peer_runtime.rs:897`;
  `crates/approval-core/src/lib.rs:470`.
- Signed event validation checks old/new bounded windows, stable full lineage,
  changed nonce, issuance before old expiry, increasing issuance and expiry,
  and content digest. No global authentication/UAC policy timeout is weakened.
  `crates/service-protocol/src/message.rs:118`.
- Phone preflight preserves exact receiving generation and validates signed
  lineage before mutation. Replacement updates one logical request and removes
  stale full-binding native authentication/denial handles. Suppressed/missing old
  engine state stays suppressed, rather than getting a fresh alert. Pending outcome
  bindings remain original while a later lease/final resolution updates its guard.
  `crates/phone-request-core/src/inbox.rs:428,883`;
  `crates/notification-policy/src/lifecycle.rs:687`;
  `crates/android-bindings/src/effects.rs:264`.
- Renewable suppression guards survive individual expiry and checkpoints.
  Capacity loss quarantines the source lineage instead of silently forgetting
  suppression. Fresh current native source epochs retire old lineage; superseded
  epochs remain rejected. Source tables are bounded and fail closed at capacity.
  `crates/phone-request-core/src/inbox.rs:1056,1168,1192`.
- Provider field mapping uses exact UIA LabeledBy Name, not text order or path-like
  application names. Linked label is PID-checked, bounded, nonpassword and not a
  value editor; relationship metadata participates in content digest. Ambiguity
  falls back to neutral caption. Duplicate descendant button captions are omitted
  without changing native traversal ordinals or action ownership.
  `crates/windows-prompt-probe/src/ffi/uia.rs:629,691`;
  `crates/windows-service-host/src/peer_runtime/prompt.rs:281`.

### Projections and evidence

- Activity snapshot comes from the service's exclusive native journal owner,
  expires after two seconds and is bounded to 64 records/12 KiB JSON in the
  management response. `None` is unavailable, distinct from a read empty history.
  Phone verification/delivery is never projected as Windows application success.
  `crates/windows-service-host/src/peer_runtime.rs:538,1641`;
  `crates/windows-service-host/src/management_protocol.rs:14,205`;
  `crates/controller-runtime/src/pc_history.rs:8`.
- Phone connected-PC projection comes from durable native peer associations plus
  current intake liveness, not request presence or JavaScript booleans. Decoder
  bounds counts/IDs/revisions and suppresses data when catalog is unavailable.
  `crates/android-bindings/src/effects.rs:98`;
  `crates/controller-runtime/src/phone_requests.rs:132`.
- QR lab retries only zero-grid presentation failures with a fixed deadline and
  attempt cap; multiple/invalid QR remains terminal. Comparison requires repeated
  stable pixel reads and changed valid digits fail. No comparison values, QR bytes
  or credentials are added to public diagnostics.
- `security/tamarin/PromptLeaseRenewal.spthy` states fresh-native-observation,
  hardware/authentication, time/storage and OS assumptions explicitly. No symbolic
  proof is treated here as native isolation or implementation-refinement evidence.

## Final integration pass

- Reviewed `.superloopy/evidence/20260919-finalization/phone-renewal.md` and
  `status-projection.md` against final source, not as substitutes for source review.
- Checkpoint v4 migration quarantines every legacy source epoch, including an
  epoch whose suppression row has already retired. Existing immutable rows retain
  their exact source/binding; they are not silently promoted to renewable state.
  The formatted codec rejects malformed flags, association-less renewable guards,
  retained guards belonging to superseded sources, and active rows beside pending
  outcomes. Immutable old outbox rows accept only an exact or complete newer
  logical lineage. `crates/phone-request-core/src/checkpoint_codec.rs:203,271,543`.
- Same-key replacement ordering remains coherent: poll/expiry/outcome handling
  uses the old binding before installing the new window; active renewal emits
  Restore, old native locators/auth/denial handles are cancelled first, and an
  explicit policy/terminal withdrawal dominates Restore.
  `crates/phone-request-core/src/inbox.rs:950`;
  `crates/android-bindings/src/effects.rs:267,291`.
- Authored regressions specifically cover migrated expired suppression followed
  by latest renewal, active off-hours boundary followed by restart/hours-on,
  expired recovery lease, and acknowledged old-expiry outbox suppression.
  `crates/phone-request-core/tests/renewal.rs:278,401,440,466`.
  These tests were inspected, not executed by this reviewer.
- Final native fixture requires an original lease no longer than 110 seconds,
  holds the real CI consent request for 115 seconds while servicing TLS, checks
  every renewal signature and exact predecessor/full lineage, requires at least
  one renewal, then signs only the latest fresh binding. A resolution during hold,
  invalid signature, changed metadata, stale event, or missing renewal fails.
  `tools/ci-phone-fixture/src/session.rs:95,106,141,171`. Existing 120-second
  frame and 300-second correlation bounds cover the hold; the outer fixture
  budget was explicitly increased to 420 seconds. No authentication TTL was
  widened. Actual proof execution belongs to ROOT.
- Android USB implementation remained unchanged from the first reviewed slice.
  Windows courier still enforces the medium token at both entry points and the
  bounded fixed-frame one-way carrier. Formatted final locations:
  `crates/windows-service-host/src/ffi/usb_bootstrap.rs:90,156,446`.

## Required validation after this static gate

1. ROOT's actual CI execution: fmt, Clippy -D warnings, Rust Analyzer, Cargo Deny,
   protocol prover with honest traces/broken controls, native gallery and installer.
2. Any subsequent architecture change requires ROOT's integration validation and
   review of altered security invariants; this verdict names the commit above.
3. Actual USB AOA support/Windows driver matrix, Android permission lifecycle,
   user UAC approval and phone authentication remain unverified by this source pass.

## Post-review availability correction: accepted

Reviewed the status_projection working-tree delta after the commit above in
`crates/phone-request-core/src/inbox.rs`, `src/checkpoint_codec.rs`, and
`tests/renewal.rs`. **PASS for this exact correction**; no validator was run.

The initial migration conservatively blocked every unknown request in a legacy
source epoch. That also blocked unrelated fresh initial requests during a
PC-first/phone-second upgrade. The corrected permanent lineage quarantine rejects
only unknown **Renewed** events. All three guard-admission call sites derive this
flag from the actual verified `PcEvent::Renewed` discriminant, not from a UI field
or the merged internal `EventKind::Opened`.

This distinction preserves replay/suppression protection:

- Old guard retirement requires a persisted service watermark at or beyond its
  original expiry. Replaying the original signed Opened cannot change that expiry
  and still reaches the source-expired drop. If it installs a new body-free marker,
  a later renewal of that marker remains suppressed (`old_metadata == None` cannot
  become active in `NotificationEngine::renew`).
- A truly independent initial Opened still passes full source, receiving-generation,
  clock, finite quarantine and capacity checks and receives its own durable marker.
  Its subsequent known renewal uses the unchanged exact-lineage replacement path.
- Unknown Renewed remains rejected because its later deadline could otherwise
  outlive forgotten legacy suppression. The service's reconnect publisher keeps
  `PcEvent::Renewed` whenever `live.renewal` exists; it never relabels the newest
  lease as an initial Opened (`peer_runtime.rs:1090`).
- Added regression source checks unknown renewal rejection, independent initial
  Show, replayed old initial Expired, inactive subsequent old renewal, independent
  known Restore, and capacity-full rejection despite the new initial distinction.

No counterexample was found under the intact-service signed-event assumptions.
Legacy already-open prompts can still require a new prompt after upgrade, but
unrelated new requests no longer require restarting the PC service. ROOT must
include this accepted delta in the actual validated release commit.

No Secure Desktop, UAC, LSA protection, boot protection or Windows policy disabling
was found in the inspected diff. Existing excluded compromised SYSTEM/kernel cases
were not treated as blockers. Line references describe the working tree at this pass
and may shift during the remaining implementation/formatting work.
