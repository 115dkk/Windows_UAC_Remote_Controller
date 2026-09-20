# Phone lease renewal implementation — 2026-09-19

## Scope and authority

ROOT approved a stable logical RequestId with separately signed bounded leases: same PC, service epoch, OS session and content digest; fresh nonce and increasing issuance/expiry. The Windows prompt worker/protocol owner supplies the privileged native same-prompt evidence and frozen eligible-device set. This slice consumes that verified protocol event; it does not establish native prompt provenance.

## Implementation

- `PhoneInbox::receive_opened_from` accepts signed `Renewed` through the existing native association-generation path. Preflight checks the original source before mutating clocks/policy. Existing rows require a renewable lineage, complete immutable logical identity, newer issuance/expiry and a matching or monotonically later signed predecessor. Missing intermediate leases are permitted; stale/forked old bindings are rejected. Exact duplicates retain their existing mapping.
- Associated initial requests persist a renewable-lineage marker. Ordinary lease expiry, schedule suppression, process restart, phone reboot, outcome acknowledgment and later clock-first reconnect cannot erase it or make it active again. Final authenticated resolution or a fresh current native source epoch ends the lineage. Old superseded epochs remain rejected.
- Previously unseen latest signed renewal may be admitted through an associated native source, but only when its source is not quarantined or superseded. Capacity-dropped associated requests set a bounded per-source quarantine bit that survives all old lease deadlines. Source/guard capacity exhaustion remains fail-closed; no unbounded request-ID collection was added.
- Notification lifecycle has an explicit metadata replacement transition. A still-active, policy-allowed lease emits `Restore`, not `Show`, without cancellation/expiry history. Missing, expired or suppressed old engine state is replaced only by suppression. Final resolution can skip unseen leases and preserves at most one logical outcome.
- New full request windows revoke previously held native request/authentication leases. Android effect dispatch cancels pruned old handles before publishing the committed same-key `Restore`; explicit policy/terminal withdrawal still takes precedence.
- Existing terminal outbox rows remain immutable even when the inactive guard advances through later signed leases. Checkpoint consistency permits only the same complete logical lineage with increasing signed issuance/expiry and no active body beside a pending terminal outcome.

## Persistence / migration

Inbox checkpoint schema 4 stores one renewal bit per retained guard and source quarantine/superseded flags. Existing byte/count bounds remain in force; source and guard slots are not evicted to regain availability.

Legacy schema 1/2/3 source epochs lack renewal-suppression provenance and are quarantined against **unknown Renewed** events. Independent signed initial **Opened** events remain subject to the existing source-watermark, finite-quarantine and capacity gates and receive a new persistent lineage marker; their subsequent known-lineage renewals work normally. This distinction prevents a PC-first/phone-second upgrade from silently hiding unrelated new requests. The trusted service never relabels a renewed snapshot as an initial Opened event. A stale original Opened still fails its expiry watermark or retained suppression marker.

Existing immutable leases may finish, but legacy rows are never silently upgraded to renewable ones. A fresh current service epoch removes the unknown-renewal uncertainty. An already-open pre-upgrade UAC request can require closing it on the PC and opening a new request (or restarting the PC service after updating the phone). Old suppressed requests are not revived.

Unassociated legacy `receive_opened` remains a one-shot immutable-lease seam and rejects renewal; it cannot invent an enrolled receiving source. Production native intake already uses the associated path.

## Authored regression coverage

- Timely same-key renewal emits Restore only, invalidates original full window, rejects stale binding/source mismatch, and treats exact repeats idempotently.
- Off-hours suppression persists across old deadline, newer source clock, process restart and missed intermediate renewal.
- Legacy source guard retirement does not allow latest renewal to become unseen/admissible. A fresh independent Opened and its later known-lineage renewal work in the same quarantined legacy epoch; replayed old Opened and subsequent suppressed renewal remain inactive.
- Known final resolution can skip renewal and records one outcome; acknowledgment of old local-expiry history never removes renewable suppression.
- Active off-hours crossing withdraws without history and cannot be restored by later hours-on renewal; expired recovery leases remain suppressed.
- Capacity quarantine persists past old leases; native current epoch replacement retires old lineage and rejects superseded epoch traffic.
- Notification engine tests cover active refresh and missing/suppressed old-state refusal.
- Legacy binary fixture helpers strip the new v4 fields deliberately before testing older codecs; v4 bounded-overhead expectations updated.

## Verification boundary

No builds, tests, fmt, lint, Rust Analyzer, executable checks or native device QA were executed by this child. Source was inspected and tests were authored only. ROOT owns formatting/CI and actual artifact/native review. Static peer review found the replacement/outbox ordering coherent and requested the off-hours/recovery/ACK regressions included above. Actual UAC approval and phone authentication remain user acceptance items.

## CI feedback correction: queued denial after source epoch replacement

ROOT reported that Linux Rust CI for `89d8481` failed `authenticated_new_service_epoch_stops_a_queued_denial_progress_record` at `denial_send.rs:362`. Source inspection shows this was the shared helper's `active() == 1` assertion, not evidence of an unsafe send: the test had already checked that the queued denial stopped, the old socket context was invalid, and no complete decision frame reached the peer.

The helper models socket-only cancellation, where the independent request stays active. Authenticated source-epoch replacement now deliberately retires the old renewable request and body while preserving a superseded source marker. The narrow test correction requires the exact `RecoveryRejected` withdrawal; zero active/retained/body/recovering request counts; two source markers; empty outcome outbox and history. All stopped/no-stale-send assertions remain. No production code was changed for this feedback, and this child did not rerun validation; the corrected expectation awaits ROOT CI.
