# Alpha.39 remaining-delta static security review

Date: 2026-09-20. Reviewer: security_review (independent child).
Baseline: `2926af0301b0e7f7b37a22083ba716bbcaa0c939`.
Reviewed implementation: `1310446a4214f0afddca5b9c90b62378fd2ccf3e`.

## Verdict

**PASS for the reviewed remaining delta. No must-fix security finding.**
This receipt covers ROOT's offline Android PC removal, exact terminal history,
display-only connection continuity, and PC readiness/journal changes. Startup
and notification-action findings/fixes have separate receipts in this directory.
No product files were edited during this pass. No builds, tests, formatting,
lint, native/device operations or subagents were run.

The actual physical notification exception and cold-boot failure condition remain
unverified. Source corrections and synthetic CI cannot establish that either
physical incident has been reproduced or resolved. Already-admitted notification
actions remain cancellation/cleanup-only; no decision or old PendingIntent replay
is authorized by the new display-ticket recovery.

## Offline removal

- `crates/android-bindings/src/peer_removal.rs` accepts only a 64-character
  lowercase hexadecimal public PC ID. It parses into fixed 32-byte storage;
  invalid/unknown/zero identity returns false. No pathname, key, file, signing
  input, clock or authorization result is accepted.
- Native admission serializes lookup/removal. The current durable association
  reference, including its generation, is resolved inside `with_inbox`, not
  supplied by presentation. `revoke_peer_association_from_trusted_host` performs
  the existing durable candidate commit and lease reconciliation
  (`crates/android-controller/src/owner.rs:467,522`). It does not delete shared
  device keys or require a PC/network acknowledgment.
- Storage ambiguity propagates through `with_inbox`'s existing fail-closed path
  (`crates/android-bindings/src/effects.rs:537`). Success is returned only after
  durable removal, exact-reference intake retirement and downward presentation/
  action cancellation have been requested. The result does not assert that an
  in-flight OS socket/crypto handle has already drained.
- `intake.rs:193` retires only peers matching the removed reference, clears their
  active/connected display state and cancels their owned stop token. It retains
  normal asynchronous I/O cleanup. Revoked native request leases are pruned by
  `dispatch_effects`, whose existing withdrawals cancel original approval/denial
  operations without dropping their cleanup obligations.
- Existing connection maintenance resolves the current durable ledger; removal
  does not create a new dial target or authorize re-enrollment. Core association,
  approval, denial and send tests already exercise revocation invalidation. The
  new bindings test explicitly removes an offline PC without creating a carrier
  or signing, rejects malformed/unknown IDs and returns false on repeated removal.

## Origin, output truth and UI

The Tauri remove command captures native `CommandOrigin`, retains normal command
admission, and calls the existing origin-bound mobile plugin transport. The
plugin dispatch snapshots the exact physical Activity/WebView adapter before
asynchronous work. JSON permits exactly the bounded `pcId` field; extra/trailing
values fail. The Application uses its existing actor; it does not create a second
owner or start a service for removal.

The actor serializes REMOVE_PEER through its existing queue/deadline/owner state.
Only a true committed `PeerRemoved` result becomes `status:ok`; stale host binding,
timeout, false removal or storage/owner failure is unconfirmed. Rust's strict
reply decoder and final owner observation withhold capability/data when the owner
is no longer ready. UI removal waits for confirmation and the actual returned
snapshot, and is available for an offline peer. Confirmation is presentation,
not a new enrollment/signing authority.

Sources: `src-tauri/src/commands.rs:187`, `src-tauri/src/mobile.rs` RemovePeer,
`src-tauri/src/mobile/snapshot.rs:68`, native Android
`DeviceStatePlugin.kt:69`, `DeviceStateActivityCommands.kt:334`,
`ControllerApplication.kt:560`, `background/ApplicationPolicyActor.kt:444,553`.

## Exact authenticated terminal history

- `phone-request-core/src/inbox.rs:1079` maps the verified PC resolution to
  Approved, Denied or Failed separately. The phone's button choice, generated
  signature, queueing or socket write cannot synthesize those terminal outcomes.
  Existing policy suppression/expiry rules and at-most-once outcome retention
  remain unchanged.
- Notification policy emits matching `ApprovedByPc`, `DeniedByPc`, `FailedByPc`
  outcomes only from the explicit authenticated-resolution transition. Withdrawal
  still has its ordinary terminal cleanup role; it is not authentication evidence.
- Both outbox and activity-history codecs preserve legacy tag 4 as unknown
  `CompletedByPc`; new tags 5/6/7 carry Approved/Denied/Failed. Existing 1/2/3 and
  version meanings are not reassigned, and unknown tags remain invalid. Pending
  outbox IDs still hash the full original binding, issuance and outcome tag, and
  checkpoint decoding reconstructs/verifies those IDs.
- `activity-journal/src/outcome_history.rs` retains body-free immutable outcome
  records and existing duplicate/conflict handling. `controller-runtime/src/
  phone_history.rs` maps exact new kinds while legacy `pc_completed` remains
  unknown. No older completion is upgraded to approval from a local choice.
- Test sources cover each terminal result, original outbox/history mappings,
  legacy tag roundtrip, unknown tag rejection, and signed peer integration where
  history stays empty before the authenticated PC terminal event. These were
  inspected, not executed by this reviewer.

## Connection labels and PC journal

- `ui/src/useConnectionDisplay.ts` holds a prior connected display for at most
  ten continuous seconds of negative observation; initial unknown/disconnected,
  identity/revision replacement and owner-stop invalidation do not gain positive
  state. Its callers only render labels or an empty-state warning. Request cards,
  command admission, disabled/action flags, native authentication and request
  expiry continue using the unmodified snapshot/native owners.
- PC connected state now additionally requires peer readiness and an actually
  drained authenticated clock response (`peer_runtime.rs:1583,1696`), not merely
  a live allocated peer. It remains connection evidence, not phone authentication
  or UAC approval evidence.
- `PromptProgress::delivery_failed` is true only for an observed new request with
  zero queued recipients. Periodic clocks, renewal witnesses and idle/resolution
  progress do not generate this failure row. This is zero-queue evidence, not a
  claim about a later TCP delivery acknowledgment.
- `ServiceOutcome::Started` is recorded after the actual Ready handshake and
  cancellation check (`windows-service-host/src/runtime.rs:262`). Later listener/
  watcher errors retain separate failure handling; Started does not prove native
  UAC execution or later service continuity.

## Remaining validation

ROOT must validate this exact implementation through CI, including updated
generated Android bridge ABI, Kotlin policy/queue tests, Rust revocation/outbox/
history tests, protocol security gates and actual UI artifacts. Physical USB,
notification/biometric/UAC acceptance and cold-boot reproduction remain separate
user-authorized observations. No additional credential/policy relaxation, signing
surface or privileged execution API was introduced by this reviewed delta.
