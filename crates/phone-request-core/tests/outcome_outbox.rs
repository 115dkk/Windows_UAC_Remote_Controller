// SPDX-License-Identifier: GPL-2.0-or-later
//! Pure signed synthetic fixtures. No journal, OS notification, native key or
//! durable delivery is performed by these core tests.

use std::{collections::BTreeSet, sync::Arc};

use approval_protocol::{
    BootEpoch, ChallengeNonce, ExpiryTick, OsSession, PcIdentity, RequestBinding, RequestContent,
    RequestId,
};
use notification_policy::{RequestOutcome, Schedule, Weekday};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use phone_request_core::{
    AlertMode, CapacityLimits, ClockReading, Effect, InboxCheckpoint, InboxCheckpointError,
    InboxClock, InboxIssue, LocalTime, MonotonicTime, NotificationPolicy, OutcomeAcknowledgment,
    PhoneBootId, PhoneInbox, request_key,
};
use service_protocol::{
    ClockCorrelation, ClockProbe, PcEvent, PcPublicKey, RequestResolution, ServiceTick,
    UnsignedPcEvent, VerifiedPcEvent,
};
use sha2::{Digest, Sha256};

const MILLI: u64 = 1_000_000;
const OUTCOME_ROW_BYTES: usize = 32 + 180 + 8 + 1;
const BODY_MARKER: &str = "SYNTHETIC_BODY_NOT_A_JOURNAL_ENTRY";

fn pc(value: u16) -> PcIdentity {
    let mut bytes = [0; 32];
    bytes[..2].copy_from_slice(&value.to_be_bytes());
    PcIdentity::from_bytes(bytes).unwrap()
}
fn epoch() -> BootEpoch {
    BootEpoch::from_bytes([2; 32]).unwrap()
}
fn boot(value: u32) -> PhoneBootId {
    PhoneBootId::from_native_boot_count(value).unwrap()
}
fn clock(ms: u64) -> InboxClock {
    InboxClock::new(
        ClockReading::new(
            MonotonicTime::from_millis(ms),
            LocalTime::new(Weekday::Monday, 600).unwrap(),
        ),
        ms * MILLI,
    )
    .unwrap()
}
fn inbox(policy: NotificationPolicy, limits: CapacityLimits) -> PhoneInbox {
    PhoneInbox::with_phone_boot(policy, limits, boot(7))
}
fn verified(event: PcEvent) -> VerifiedPcEvent {
    let expected = event.pc();
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let public =
        PcPublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    let unsigned = UnsignedPcEvent::new(event).unwrap();
    let signature: Signature = key.sign(&unsigned.signing_bytes());
    unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
        .verify(expected, &public)
        .unwrap()
}
fn source(peer: u16, phone_ms: u64, service_ms: u64) -> ClockCorrelation {
    let probe = ClockProbe::start(pc(peer), phone_ms * MILLI).unwrap();
    let response = verified(PcEvent::Clock {
        pc: pc(peer),
        epoch: epoch(),
        probe: probe.nonce(),
        sampled_at: ServiceTick::from_nanos_since_epoch(service_ms * MILLI),
    });
    probe.complete(&response, phone_ms * MILLI).unwrap()
}
fn opened(peer: u16, id: u64, issued: u64, expiry: u64) -> VerifiedPcEvent {
    let content = Arc::new(
        RequestContent::new(
            "Synthetic outbox app",
            "C:\\Synthetic\\outbox.exe",
            BODY_MARKER,
        )
        .unwrap(),
    );
    let mut request = [0; 32];
    request[..8].copy_from_slice(&id.to_be_bytes());
    let binding = RequestBinding::new(
        pc(peer),
        epoch(),
        OsSession::new(3, 9),
        RequestId::from_bytes(request).unwrap(),
        ChallengeNonce::from_bytes([5; 32]).unwrap(),
        content.digest(),
        ExpiryTick::from_nanos_since_epoch(expiry * MILLI).unwrap(),
    );
    verified(PcEvent::Opened {
        binding,
        issued_at: ServiceTick::from_nanos_since_epoch(issued * MILLI),
        content,
    })
}
fn resolved(event: &VerifiedPcEvent, outcome: RequestResolution) -> VerifiedPcEvent {
    let PcEvent::Opened {
        binding, issued_at, ..
    } = event.event()
    else {
        panic!("opened fixture")
    };
    verified(PcEvent::Resolved {
        binding: *binding,
        issued_at: *issued_at,
        outcome,
    })
}
fn key(event: &VerifiedPcEvent) -> notification_policy::RequestKey {
    let PcEvent::Opened { binding, .. } = event.event() else {
        panic!("opened fixture")
    };
    request_key(*binding)
}
fn no_show_or_history(effects: &[Effect]) {
    assert!(effects.iter().all(|effect| !matches!(
        effect,
        Effect::Show(_) | Effect::Restore(_) | Effect::RecordOutcome { .. }
    )));
}
fn one_pending() -> (PhoneInbox, VerifiedPcEvent) {
    let mut state = inbox(NotificationPolicy::default(), CapacityLimits::default());
    let event = opened(1, 1, 0, 1_000);
    state.receive_opened(&event, &mut source(1, 0, 0), clock(0));
    state.resolve_pc(
        &resolved(&event, RequestResolution::Cancelled),
        &mut source(1, 0, 0),
        clock(1),
    );
    assert_eq!(state.pending_outcomes().len(), 1);
    (state, event)
}
fn legacy_without_outbox(state: &PhoneInbox) -> Vec<u8> {
    let mut bytes = state.checkpoint().unwrap().to_bytes().unwrap();
    let tail = 2 + state.pending_outcomes().len() * OUTCOME_ROW_BYTES;
    bytes.truncate(bytes.len() - tail);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes
}

#[test]
fn delivery_identity_is_the_published_canonical_binding_issuance_and_outcome_hash() {
    let (state, event) = one_pending();
    let row = state.pending_outcomes()[0];
    let PcEvent::Opened {
        binding: original,
        issued_at,
        ..
    } = event.event()
    else {
        panic!("opened fixture")
    };
    assert_eq!(row.binding(), *original);
    assert_eq!(row.issued_at(), *issued_at);
    let binding = row.binding();
    let mut canonical = b"Windows-UAC-Remote-Controller/outcome-delivery/v1\0".to_vec();
    canonical.extend_from_slice(binding.pc().as_bytes());
    canonical.extend_from_slice(binding.epoch().as_bytes());
    canonical.extend_from_slice(&binding.session().session_id().to_be_bytes());
    canonical.extend_from_slice(&binding.session().logon_id().to_be_bytes());
    canonical.extend_from_slice(binding.request_id().as_bytes());
    canonical.extend_from_slice(binding.nonce().as_bytes());
    canonical.extend_from_slice(binding.content_digest().as_bytes());
    canonical.extend_from_slice(&binding.expiry().as_nanos_since_epoch().to_be_bytes());
    canonical.extend_from_slice(&row.issued_at().as_nanos_since_epoch().to_be_bytes());
    canonical.push(1); // Fixed CancelledByPc discriminant, not Rust Debug/JSON.
    let expected = Sha256::digest(canonical);
    assert_eq!(&row.delivery_id().as_bytes()[..], &expected[..]);
    assert!(!format!("{row:?} {:?}", row.delivery_id()).contains(BODY_MARKER));
}

#[test]
fn each_existing_terminal_kind_has_a_stable_distinct_delivery_identity() {
    let event = opened(1, 9, 0, 1_000);
    let mut ids = BTreeSet::new();
    for (resolution, expected) in [
        (
            Some(RequestResolution::Cancelled),
            RequestOutcome::CancelledByPc,
        ),
        (
            Some(RequestResolution::Expired),
            RequestOutcome::ExpiredByPc,
        ),
        (
            Some(RequestResolution::Denied),
            RequestOutcome::CompletedByPc,
        ),
        (None, RequestOutcome::ExpiredLocally),
    ] {
        let mut state = inbox(NotificationPolicy::default(), CapacityLimits::default());
        state.receive_opened(&event, &mut source(1, 0, 0), clock(0));
        if let Some(resolution) = resolution {
            state.resolve_pc(
                &resolved(&event, resolution),
                &mut source(1, 0, 0),
                clock(1),
            );
        } else {
            state.poll(clock(1_000));
        }
        let row = state.pending_outcomes()[0];
        assert_eq!(row.outcome(), expected);
        assert!(ids.insert(row.delivery_id()));
        let saved =
            InboxCheckpoint::from_bytes(&state.checkpoint().unwrap().to_bytes().unwrap()).unwrap();
        let (restored, update) = PhoneInbox::restore_checkpoint(saved, boot(8), clock(0)).unwrap();
        assert_eq!(restored.pending_outcomes(), &[row]);
        no_show_or_history(update.effects());
    }
}

#[test]
fn pending_outcome_survives_guard_retirement_and_cannot_resurrect_on_ack() {
    let (mut state, event) = one_pending();
    let row = state.pending_outcomes()[0];
    let retired = state.observe_service_clock(&source(1, 1_001, 1_000), clock(1_001));
    no_show_or_history(retired.effects());
    assert_eq!(state.retained_count(), 0);
    assert_eq!(state.pending_outcomes(), &[row]);
    let saved =
        InboxCheckpoint::from_bytes(&state.checkpoint().unwrap().to_bytes().unwrap()).unwrap();
    assert!(!saved.is_policy_only());
    let (mut restored, update) = PhoneInbox::restore_checkpoint(saved, boot(8), clock(0)).unwrap();
    no_show_or_history(update.effects());
    assert_eq!(restored.pending_outcomes(), &[row]);
    assert_eq!(
        restored.acknowledge_outcome(row.delivery_id()),
        OutcomeAcknowledgment::Removed
    );
    let duplicate = restored.receive_opened(&event, &mut source(1, 0, 0), clock(0));
    no_show_or_history(duplicate.effects());
    assert!(restored.pending_outcomes().is_empty());
}

#[test]
fn off_hours_and_schedule_suppression_make_no_outcome_or_retained_body() {
    let mut state = inbox(
        NotificationPolicy::new(Some(Schedule::Never), AlertMode::Sound),
        CapacityLimits::default(),
    );
    let event = opened(1, 10, 0, 10_000);
    let weak = match event.event() {
        PcEvent::Opened { content, .. } => Arc::downgrade(content),
        _ => unreachable!(),
    };
    no_show_or_history(
        state
            .receive_opened(&event, &mut source(1, 0, 0), clock(0))
            .effects(),
    );
    assert!(state.pending_outcomes().is_empty());
    drop(event);
    assert!(weak.upgrade().is_none());
    state.update_policy(NotificationPolicy::default(), clock(1));
    no_show_or_history(
        state
            .receive_opened(&opened(1, 10, 0, 10_000), &mut source(1, 0, 0), clock(2))
            .effects(),
    );
    assert!(state.pending_outcomes().is_empty());

    let active = opened(1, 11, 0, 10_000);
    state.receive_opened(&active, &mut source(1, 0, 0), clock(3));
    let withdrawn = state.update_policy(
        NotificationPolicy::new(Some(Schedule::Never), AlertMode::Sound),
        clock(4),
    );
    no_show_or_history(withdrawn.effects());
    assert_eq!(state.retained_body_count(), 0);
    assert!(state.pending_outcomes().is_empty());
}

#[test]
fn active_and_recovering_requests_reserve_one_slot_and_capacity_drop_stays_suppressed() {
    let limits = CapacityLimits::new(1, 2).unwrap();
    let mut state = inbox(NotificationPolicy::default(), limits);
    let first = opened(1, 20, 0, 1_000);
    let active = opened(1, 21, 0, 2_000);
    state.receive_opened(&first, &mut source(1, 0, 0), clock(0));
    state.resolve_pc(
        &resolved(&first, RequestResolution::Cancelled),
        &mut source(1, 0, 0),
        clock(1),
    );
    state.receive_opened(&active, &mut source(1, 0, 0), clock(2));
    state.observe_service_clock(&source(1, 1_001, 1_000), clock(1_001));
    assert_eq!(state.retained_count(), 1);
    assert_eq!(state.pending_outcomes().len(), 1);
    let saved =
        InboxCheckpoint::from_bytes(&state.checkpoint().unwrap().to_bytes().unwrap()).unwrap();
    // Exercise two pure branches from the same pre-admission checkpoint. A real
    // native owner never duplicates its live store or accepts uncommitted drops.
    let blocked = opened(1, 22, 1_000, 2_500);
    let active_capacity =
        state.receive_opened(&blocked, &mut source(1, 1_001, 1_000), clock(1_002));
    assert_eq!(active_capacity.issue(), Some(InboxIssue::OutcomeCapacity));
    no_show_or_history(active_capacity.effects());
    drop(state);
    let (mut restored, _) = PhoneInbox::restore_checkpoint(saved, boot(7), clock(1_002)).unwrap();
    assert_eq!(restored.active_count(), 0);
    assert_eq!(restored.recovering_count(), 1);
    let update = restored.receive_opened(&blocked, &mut source(1, 1_001, 1_000), clock(1_003));
    assert_eq!(update.issue(), Some(InboxIssue::OutcomeCapacity));
    no_show_or_history(update.effects());
    let restored_body =
        restored.receive_opened(&active, &mut source(1, 1_001, 1_000), clock(1_004));
    assert!(
        restored_body
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Restore(_)))
    );
    assert_eq!(restored.active_count(), 1);
    assert_eq!(restored.recovering_count(), 0);
    let first_id = restored.pending_outcomes()[0].delivery_id();
    assert_eq!(
        restored.acknowledge_outcome(first_id),
        OutcomeAcknowledgment::Removed
    );
    no_show_or_history(
        restored
            .receive_opened(&blocked, &mut source(1, 1_001, 1_000), clock(1_005))
            .effects(),
    );
    assert!(restored.pending_outcomes().is_empty());
    restored.poll(clock(2_000));
    assert_eq!(restored.pending_outcomes().len(), 1);
    assert_eq!(restored.pending_outcomes()[0].key(), key(&active));
    assert!(restored.fault().is_none());
    assert!(restored.checkpoint().unwrap().to_bytes().is_ok());
}

#[test]
fn reserved_completions_can_fill_the_outbox_without_losing_an_outcome() {
    let mut state = inbox(
        NotificationPolicy::default(),
        CapacityLimits::new(2, 2).unwrap(),
    );
    let first = opened(1, 30, 0, 1_000);
    let second = opened(1, 31, 0, 1_000);
    state.receive_opened(&first, &mut source(1, 0, 0), clock(0));
    state.receive_opened(&second, &mut source(1, 0, 0), clock(0));
    let expired = state.poll(clock(1_000));
    assert_eq!(
        expired
            .effects()
            .iter()
            .filter(|effect| matches!(effect, Effect::RecordOutcome { .. }))
            .count(),
        2
    );
    assert_eq!(state.pending_outcomes().len(), 2);
    assert_eq!(state.retained_body_count(), 0);
    assert!(state.fault().is_none());
    assert!(state.checkpoint().unwrap().to_bytes().is_ok());
}

#[test]
fn unknown_ack_and_duplicate_terminal_events_do_not_mean_delivered_or_add_rows() {
    let (mut state, event) = one_pending();
    let row = state.pending_outcomes()[0];
    let mut other = inbox(NotificationPolicy::default(), CapacityLimits::default());
    let other_event = opened(2, 1, 0, 1_000);
    other.receive_opened(&other_event, &mut source(2, 0, 0), clock(0));
    other.resolve_pc(
        &resolved(&other_event, RequestResolution::Cancelled),
        &mut source(2, 0, 0),
        clock(1),
    );
    let unknown = other.pending_outcomes()[0].delivery_id();
    assert_ne!(unknown, row.delivery_id());
    assert_eq!(
        state.acknowledge_outcome(unknown),
        OutcomeAcknowledgment::NotPending
    );
    assert_eq!(state.pending_outcomes(), &[row]);
    no_show_or_history(
        state
            .resolve_pc(
                &resolved(&event, RequestResolution::Approved),
                &mut source(1, 0, 0),
                clock(2),
            )
            .effects(),
    );
    assert_eq!(state.pending_outcomes(), &[row]);
}

#[test]
fn schema1_migration_is_only_for_fully_valid_policy_only_state() {
    let policy_only = inbox(NotificationPolicy::default(), CapacityLimits::default());
    let legacy = legacy_without_outbox(&policy_only);
    let migrated = InboxCheckpoint::from_bytes(&legacy).unwrap();
    assert!(migrated.is_policy_only());
    assert_eq!(&migrated.to_bytes().unwrap()[8..10], &2_u16.to_be_bytes());
    let mut corrupt = legacy.clone();
    corrupt.push(0);
    assert!(InboxCheckpoint::from_bytes(&corrupt).is_err());
    let mut missing_policy = legacy;
    missing_policy[18..22].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(InboxCheckpoint::from_bytes(&missing_policy).is_err());

    let mut active = inbox(NotificationPolicy::default(), CapacityLimits::default());
    active.receive_opened(&opened(1, 40, 0, 1_000), &mut source(1, 0, 0), clock(0));
    assert_eq!(
        InboxCheckpoint::from_bytes(&legacy_without_outbox(&active)).unwrap_err(),
        InboxCheckpointError::LegacyOutcomeReconciliationRequired
    );
    let (terminal, _) = one_pending();
    assert_eq!(
        InboxCheckpoint::from_bytes(&legacy_without_outbox(&terminal)).unwrap_err(),
        InboxCheckpointError::LegacyOutcomeReconciliationRequired
    );
}

#[test]
fn outbox_codec_rejects_id_field_outcome_count_duplicate_and_trailing_corruption() {
    let (state, event) = one_pending();
    let bytes = state.checkpoint().unwrap().to_bytes().unwrap();
    assert!(
        !bytes
            .windows(BODY_MARKER.len())
            .any(|part| part == BODY_MARKER.as_bytes())
    );
    let row = bytes.len() - OUTCOME_ROW_BYTES;
    let count = row - 2;
    for offset in [row, row + 32, row + 32 + 180, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[offset] ^= 0x80;
        assert!(InboxCheckpoint::from_bytes(&changed).is_err());
    }
    for end in count..bytes.len() {
        assert!(InboxCheckpoint::from_bytes(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(InboxCheckpoint::from_bytes(&trailing).is_err());
    let mut excessive = bytes.clone();
    excessive[count..row].copy_from_slice(&513_u16.to_be_bytes());
    assert!(InboxCheckpoint::from_bytes(&excessive).is_err());
    let mut duplicate = bytes.clone();
    duplicate[count..row].copy_from_slice(&2_u16.to_be_bytes());
    duplicate.extend_from_slice(&bytes[row..]);
    assert!(InboxCheckpoint::from_bytes(&duplicate).is_err());

    let mut other = inbox(NotificationPolicy::default(), CapacityLimits::default());
    other.receive_opened(&event, &mut source(1, 0, 0), clock(0));
    other.resolve_pc(
        &resolved(&event, RequestResolution::Expired),
        &mut source(1, 0, 0),
        clock(1),
    );
    let other_bytes = other.checkpoint().unwrap().to_bytes().unwrap();
    let mut conflicting = bytes.clone();
    conflicting[count..row].copy_from_slice(&2_u16.to_be_bytes());
    conflicting.extend_from_slice(&other_bytes[other_bytes.len() - OUTCOME_ROW_BYTES..]);
    assert!(
        InboxCheckpoint::from_bytes(&conflicting).is_err(),
        "same request key with a distinct valid outcome ID"
    );
}

#[test]
fn maximum_pending_rows_plus_guards_and_sources_stay_inside_the_existing_byte_cap() {
    let mut state = inbox(
        NotificationPolicy::default(),
        CapacityLimits::new(32, 512).unwrap(),
    );
    for peer in 1..=512_u16 {
        let event = opened(peer, 1, 0, 60_000);
        let admitted = state.receive_opened(&event, &mut source(peer, 0, 0), clock(0));
        assert!(
            admitted
                .effects()
                .iter()
                .any(|effect| matches!(effect, Effect::Show(_)))
        );
        state.resolve_pc(
            &resolved(&event, RequestResolution::Cancelled),
            &mut source(peer, 0, 0),
            clock(0),
        );
    }
    assert_eq!(state.pending_outcomes().len(), 512);
    assert_eq!(state.retained_count(), 512);
    assert_eq!(state.source_count(), 512);
    assert_eq!(state.retained_body_count(), 0);
    let bytes = state.checkpoint().unwrap().to_bytes().unwrap();
    assert!(bytes.len() <= 384 * 1024);
    let decoded = InboxCheckpoint::from_bytes(&bytes).unwrap();
    let (restored, _) = PhoneInbox::restore_checkpoint(decoded, boot(7), clock(1)).unwrap();
    assert_eq!(restored.pending_outcomes(), state.pending_outcomes());
}
