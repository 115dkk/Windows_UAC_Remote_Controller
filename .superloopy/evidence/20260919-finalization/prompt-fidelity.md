# Prompt fidelity and bounded live-prompt leases

Implementation/static-review record only. No child builds, tests, formatters,
native executables or device checks were run. ROOT owns CI and native evidence.

## Changes

- Native RawView traversal tracks actual button ancestry, including unnamed
  containers. Only exact Text descendant echoes of a button Name are elided;
  equal sibling fields and different descendant text remain. Traversal ordinals,
  counts and exact-button lookup still visit the complete tree.
- `CurrentLabeledBy` reads one provider-authored label relationship after process,
  password and control/value checks. The bounded label participates in content
  equality, hash and the v3 private probe protocol. No linked subtree is walked.
- Program/location projection uses unique provider field labels, never text
  position or the first path-looking string. Unknown shapes retain neutral
  dialog caption and full details. Provider-labeled publisher/command lines
  remain distinct `label: value` lines without a shared request-body schema change.
- Each watcher heartbeat with a tracked target now requires two current UIA
  captures matching retained owner, runtime identity and content. A changed
  prompt is replaced; disappearance, desktop change and verification failure
  withdraw the target. Applying/consumed targets cannot issue renewal events.
- The service retains the original 110-second bounded lease. At 30 seconds
  remaining, fresh same-prompt proof permits an exact-binding renewal: stable
  RequestId lineage, fresh nonce/expiry, original content and frozen eligible
  device snapshot. Every former signature fails exact binding comparison.
- Signed `PcEvent::Renewed` replaces the phone lease atomically. It carries both
  immutable bindings and issuance ticks; validation requires stable identity,
  session and content, a changed nonce and strictly advancing overlapping lease.
  Renewal itself creates no Windows cancellation/expiry history entry.
- Phone durable lineage/suppression integration is owned by the status_projection
  peer agent. Check its evidence and tests before declaring integration complete.

## Native boundaries still requiring observation

No current Windows provider-control-ID capture was available. Automatic details
expansion is therefore not added. Reading fields exposed through LabeledBy is
implemented, but whether this Windows consent UI supplies those relationships
requires an operator/CI native capture. Unrecognized shapes keep their details
without inventing program/path identity. Korean/English field-label recognition
does not establish support for every Windows locale.

Microsoft documents LabeledBy as the element's provider-supplied text-label
relationship, with NULL as its default; that establishes the API contract, not
the fields exposed by any particular consent.exe build. Sources retrieved
2026-09-19: [CurrentLabeledBy](https://learn.microsoft.com/en-us/windows/win32/api/uiautomationclient/nf-uiautomationclient-iuiautomationelement-get_currentlabeledby),
[property defaults](https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/WinAuto/uiauto-automation-element-propids.md).

Actual Windows consent approval and actual phone hardware authentication remain
the user's acceptance tests. Pure-core tests and the symbolic model do not prove
native isolation, presentation or hardware behavior.

## Required ROOT checks

1. CI Rust fmt, Clippy `-D warnings`, real Rust Analyzer and workspace tests.
2. New approval-core renewal tests: stale nonce rejection, stable lineage,
   frozen eligibility, consumed/cancelled/expired refusal.
3. New service tests: early/wrong-target heartbeat does not renew; fresh proof
   renews before expiry without terminal history; disappearance cancels.
4. Probe tests: exact descendant-only caption suppression, LabeledBy budget,
   codec/hash coverage, v3 mixed-version rejection and aggregate limits.
5. Protocol signed-renewal round-trip and malformed/reused-binding rejection;
   phone durable tests for same-key auth invalidation, source mismatch,
   suppression across reconnect/missed renewal and final resolution.
6. Native CI consent lab held beyond 110 seconds, then closed/replaced. Confirm
   one live phone request, bounded updated countdown, no false terminal history,
   exact old-binding refusal and live native approval path.
7. Required `prompt-lease-renewal` Tamarin model: all four positives plus the
   retained-old-slot negative control. Missing/incomplete proofs fail the gate.
8. Refresh manifest source hashes only after final source/format changes. The
   current manifest entries are work-in-progress snapshots, not final receipts.

The existing native fixture metadata matcher already permits the expected
synthetic program marker in details when no provider-identified path exists;
`tools/ci-phone-fixture/src/session.rs::match_metadata` needs no weakening.
The lab_stability peer owns its new >110-second native lease-renewal exercise.

ROOT can print refreshed normalized source bindings with this read-only command,
then apply the resulting manifest via `apply_patch`:

```powershell
node --input-type=module -e 'import {readFileSync} from "node:fs"; import {createHash} from "node:crypto"; const m=JSON.parse(readFileSync("security/tamarin/manifest.json","utf8")); for(const b of m.sourceBindings) b.sha256=createHash("sha256").update(readFileSync(b.path,"utf8").replace(/\r\n/g,"\n")).digest("hex"); console.log(JSON.stringify(m,null,2));'
```

## Symbolic source mapping

`PromptLeaseRenewal.spthy` maps native same-prompt observation to the protected
watcher's double-capture/equality branch in `windows-prompt-probe/src/ffi/watch.rs`.
The stable lineage and fresh immutable lease are implemented in
`ApprovalEngine::renew_from_privileged_host`; its exclusive pending slot and
`submit_decision` exact binding comparison implement retirement/replay defense.
`ServiceSession::renew_live_prompt` is the sole production renewal producer.
`service-protocol/{message,codec}.rs` binds both old/new identities into the PC's
signature. Phone native per-use authentication remains a trusted assumption of
the model; its exact binding cannot be reused for the new nonce.

The model intentionally does not claim numerical clock accuracy, atomic UIA
snapshots, Windows/Android isolation, durable storage refinement or native
end-to-end proof. The existing request/transport theories remain mandatory.
