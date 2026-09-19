// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic signed lease lineages; not native UAC, device or authentication QA.
use approval_protocol::{
    BootEpoch, ChallengeNonce, ExpiryTick, OsSession, PcIdentity, RequestBinding, RequestContent,
    RequestId,
};
use notification_policy::{DayMask, DropReason, Schedule, TimeWindow, Weekday, WeeklySchedule};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use phone_request_core::{
    AlertMode, CapacityLimits, ClockReading, Effect, InboxCheckpoint, InboxClock, InboxIssue,
    LocalTime, MonotonicTime, NotificationPolicy, PhoneBootId, PhoneInbox, ReceivingGeneration,
    request_key,
};
use service_protocol::{
    ClockCorrelation, ClockProbe, PcEvent, PcPublicKey, RequestResolution, ServiceTick,
    UnsignedPcEvent, VerifiedPcEvent,
};
use std::sync::Arc;

#[path = "support/legacy_codec.rs"]
mod legacy_codec;

const MS: u64 = 1_000_000;
fn pc() -> PcIdentity {
    PcIdentity::from_bytes([1; 32]).unwrap()
}
fn boot() -> PhoneBootId {
    PhoneBootId::from_native_boot_count(7).unwrap()
}
fn generation(value: u64) -> ReceivingGeneration {
    ReceivingGeneration::from_trusted_owner(value).unwrap()
}
fn clock(ms: u64) -> InboxClock {
    clock_at(ms, 600)
}
fn clock_at(ms: u64, minute: u16) -> InboxClock {
    InboxClock::new(
        ClockReading::new(
            MonotonicTime::from_millis(ms),
            LocalTime::new(Weekday::Monday, minute).unwrap(),
        ),
        ms * MS,
    )
    .unwrap()
}
fn signed(event: PcEvent) -> VerifiedPcEvent {
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let public =
        PcPublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    let unsigned = UnsignedPcEvent::new(event).unwrap();
    let signature: Signature = key.sign(&unsigned.signing_bytes());
    unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
        .verify(pc(), &public)
        .unwrap()
}
fn correlation(ms: u64, epoch: u8) -> ClockCorrelation {
    let probe = ClockProbe::start(pc(), ms * MS).unwrap();
    let event = signed(PcEvent::Clock {
        pc: pc(),
        epoch: BootEpoch::from_bytes([epoch; 32]).unwrap(),
        probe: probe.nonce(),
        sampled_at: ServiceTick::from_nanos_since_epoch(ms * MS),
    });
    probe.complete(&event, ms * MS).unwrap()
}
fn opened(id: u8, epoch: u8, issued: u64, expiry: u64) -> VerifiedPcEvent {
    let content = Arc::new(
        RequestContent::new(
            "Synthetic renewal",
            "C:\\Synthetic\\renew.exe",
            "inert fixture",
        )
        .unwrap(),
    );
    let binding = RequestBinding::new(
        pc(),
        BootEpoch::from_bytes([epoch; 32]).unwrap(),
        OsSession::new(1, 2),
        RequestId::from_bytes([id; 32]).unwrap(),
        ChallengeNonce::from_bytes([5; 32]).unwrap(),
        content.digest(),
        ExpiryTick::from_nanos_since_epoch(expiry * MS).unwrap(),
    );
    signed(PcEvent::Opened {
        binding,
        issued_at: ServiceTick::from_nanos_since_epoch(issued * MS),
        content,
    })
}
fn parts(event: &VerifiedPcEvent) -> (RequestBinding, ServiceTick, Arc<RequestContent>) {
    match event.event() {
        PcEvent::Opened {
            binding,
            issued_at,
            content,
        }
        | PcEvent::Renewed {
            binding,
            issued_at,
            content,
            ..
        } => (*binding, *issued_at, Arc::clone(content)),
        _ => panic!("request fixture"),
    }
}
fn renewed(previous: &VerifiedPcEvent, nonce: u8, issued: u64, expiry: u64) -> VerifiedPcEvent {
    let (old, previous_issued_at, content) = parts(previous);
    let binding = RequestBinding::new(
        old.pc(),
        old.epoch(),
        old.session(),
        old.request_id(),
        ChallengeNonce::from_bytes([nonce; 32]).unwrap(),
        old.content_digest(),
        ExpiryTick::from_nanos_since_epoch(expiry * MS).unwrap(),
    );
    signed(PcEvent::Renewed {
        previous_binding: old,
        previous_issued_at,
        binding,
        issued_at: ServiceTick::from_nanos_since_epoch(issued * MS),
        content,
    })
}
fn final_event(event: &VerifiedPcEvent) -> VerifiedPcEvent {
    let (binding, issued_at, _) = parts(event);
    signed(PcEvent::Resolved {
        binding,
        issued_at,
        outcome: RequestResolution::Denied,
    })
}
fn inbox(policy: NotificationPolicy, limits: CapacityLimits) -> PhoneInbox {
    PhoneInbox::with_phone_boot(policy, limits, boot())
}
fn no_positive(update: &phone_request_core::InboxUpdate) {
    assert!(update.effects().iter().all(|effect| !matches!(
        effect,
        Effect::Show(_) | Effect::Restore(_) | Effect::RecordOutcome { .. }
    )));
    assert!(update.fault().is_none());
}
fn saved(inbox: &PhoneInbox) -> InboxCheckpoint {
    let bytes = inbox.checkpoint().unwrap().to_bytes().unwrap();
    assert_eq!(&bytes[8..10], &4_u16.to_be_bytes());
    InboxCheckpoint::from_bytes(&bytes).unwrap()
}

#[test]
fn timely_renewal_restores_without_history_and_invalidates_the_original_full_window() {
    let mut inbox = inbox(NotificationPolicy::default(), CapacityLimits::default());
    let first = opened(1, 2, 0, 1000);
    let key = request_key(parts(&first).0);
    inbox.receive_opened_from(&first, generation(1), &mut correlation(0, 2), clock(0));
    let old = inbox
        .check_pending(key, clock(0))
        .request()
        .unwrap()
        .original_window();
    let second = renewed(&first, 6, 900, 1900);
    let update =
        inbox.receive_opened_from(&second, generation(1), &mut correlation(900, 2), clock(900));
    assert!(
        update
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Restore(_)))
    );
    assert!(update.effects().iter().all(|effect| !matches!(
        effect,
        Effect::Show(_) | Effect::RecordOutcome { .. } | Effect::Withdraw { .. }
    )));
    assert!(!inbox.retains_exact_pending_snapshot(old, generation(1)));
    assert_eq!(
        inbox
            .check_pending(key, clock(900))
            .request()
            .unwrap()
            .original_window()
            .binding(),
        parts(&second).0
    );
    let duplicate =
        inbox.receive_opened_from(&second, generation(1), &mut correlation(901, 2), clock(901));
    no_positive(&duplicate);
    assert!(duplicate.effects().iter().any(|effect| matches!(
        effect,
        Effect::Drop {
            reason: DropReason::DuplicateActive,
            ..
        }
    )));
    let stale =
        inbox.receive_opened_from(&first, generation(1), &mut correlation(902, 2), clock(902));
    assert_eq!(stale.issue(), Some(InboxIssue::ConflictingBinding));
    let third = renewed(&second, 7, 1800, 2800);
    let wrong_source = inbox.receive_opened_from(
        &third,
        generation(2),
        &mut correlation(1800, 2),
        clock(1800),
    );
    assert_eq!(
        wrong_source.issue(),
        Some(InboxIssue::ConflictingReceivingSource)
    );
    assert!(wrong_source.effects().is_empty());
    let _ = saved(&inbox);
}

#[test]
fn suppressed_lineage_survives_clock_first_reconnect_restart_and_missed_renewals() {
    let mut inbox = inbox(
        NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent),
        CapacityLimits::default(),
    );
    let first = opened(1, 2, 0, 1000);
    let second = renewed(&first, 6, 900, 1900);
    let third = renewed(&second, 7, 1800, 2800);
    no_positive(&inbox.receive_opened_from(
        &first,
        generation(1),
        &mut correlation(0, 2),
        clock(0),
    ));
    no_positive(&inbox.observe_service_clock(&correlation(1500, 2), clock(1500)));
    assert_eq!(inbox.retained_count(), 1);
    no_positive(&inbox.update_policy(NotificationPolicy::default(), clock(1501)));
    let (mut restored, update) =
        PhoneInbox::restore_checkpoint(saved(&inbox), boot(), clock(1502)).unwrap();
    no_positive(&update);
    no_positive(&restored.receive_opened_from(
        &third,
        generation(1),
        &mut correlation(1800, 2),
        clock(1800),
    ));
    assert_eq!(restored.active_count(), 0);
    assert_eq!(restored.retained_count(), 1);
    assert!(restored.pending_outcomes().is_empty());
    let (mut restored, _) =
        PhoneInbox::restore_checkpoint(saved(&restored), boot(), clock(1801)).unwrap();
    no_positive(&restored.resolve_pc_from(
        &final_event(&third),
        generation(1),
        &mut correlation(1802, 2),
        clock(1802),
    ));
    no_positive(&restored.observe_service_clock(&correlation(3000, 2), clock(3000)));
    assert_eq!(restored.retained_count(), 0);
}

#[test]
fn unseen_latest_lease_is_admitted_but_unassociated_renewal_is_not() {
    let first = opened(1, 2, 0, 1000);
    let second = renewed(&first, 6, 900, 1900);
    let mut inbox = inbox(NotificationPolicy::default(), CapacityLimits::default());
    assert_eq!(
        inbox
            .receive_opened(&second, &mut correlation(900, 2), clock(900))
            .issue(),
        Some(InboxIssue::WrongEventKind)
    );
    let update =
        inbox.receive_opened_from(&second, generation(1), &mut correlation(900, 2), clock(900));
    assert!(
        update
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
}

#[test]
fn legacy_source_epoch_cannot_reclassify_a_retired_suppression_as_unseen_renewal() {
    let mut original = inbox(
        NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent),
        CapacityLimits::default(),
    );
    let first = opened(1, 2, 0, 1000);
    let second = renewed(&first, 6, 900, 1900);
    let third = renewed(&second, 7, 1800, 2800);
    original.receive_opened_from(&first, generation(1), &mut correlation(0, 2), clock(0));
    let old_bytes = legacy_codec::as_v3(&original.checkpoint().unwrap().to_bytes().unwrap());
    let old = InboxCheckpoint::from_bytes(&old_bytes).unwrap();
    let (mut restored, _) = PhoneInbox::restore_checkpoint(old, boot(), clock(1)).unwrap();
    no_positive(&restored.observe_service_clock(&correlation(1500, 2), clock(1500)));
    assert_eq!(restored.retained_count(), 0);
    no_positive(&restored.update_policy(NotificationPolicy::default(), clock(1501)));
    let update = restored.receive_opened_from(
        &third,
        generation(1),
        &mut correlation(1800, 2),
        clock(1800),
    );
    assert_eq!(update.issue(), Some(InboxIssue::GuardQuarantine));
    no_positive(&update);
    let _ = saved(&restored);
}

#[test]
fn final_resolution_can_skip_a_renewal_and_records_one_outcome_only() {
    let first = opened(1, 2, 0, 1000);
    let second = renewed(&first, 6, 400, 1400);
    let mut inbox = inbox(NotificationPolicy::default(), CapacityLimits::default());
    inbox.receive_opened_from(&first, generation(1), &mut correlation(0, 2), clock(0));
    let final_event = final_event(&second);
    let update = inbox.resolve_pc_from(
        &final_event,
        generation(1),
        &mut correlation(500, 2),
        clock(500),
    );
    assert!(
        update
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::RecordOutcome { .. }))
    );
    assert_eq!(inbox.pending_outcomes().len(), 1);
    assert_eq!(inbox.active_count(), 0);
    let _ = saved(&inbox);
    no_positive(&inbox.resolve_pc_from(
        &final_event,
        generation(1),
        &mut correlation(501, 2),
        clock(501),
    ));
    no_positive(&inbox.receive_opened_from(
        &second,
        generation(1),
        &mut correlation(502, 2),
        clock(502),
    ));
    assert_eq!(inbox.pending_outcomes().len(), 1);
}

#[test]
fn capacity_quarantine_persists_past_old_leases_and_epoch_replacement_retires_old_lineage() {
    let mut inbox = inbox(
        NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent),
        CapacityLimits::new(1, 2).unwrap(),
    );
    for id in [1, 2] {
        no_positive(&inbox.receive_opened_from(
            &opened(id, 2, 0, 1000),
            generation(1),
            &mut correlation(0, 2),
            clock(0),
        ));
    }
    let first = opened(3, 2, 0, 1000);
    let second = renewed(&first, 6, 900, 1900);
    let third = renewed(&second, 7, 1800, 2800);
    let drop = inbox.receive_opened_from(&first, generation(1), &mut correlation(0, 2), clock(0));
    assert_eq!(drop.issue(), Some(InboxIssue::GuardCapacity));
    no_positive(&inbox.observe_service_clock(&correlation(1700, 2), clock(1700)));
    assert!(inbox.is_quarantined());
    let (mut inbox, _) =
        PhoneInbox::restore_checkpoint(saved(&inbox), boot(), clock(1701)).unwrap();
    no_positive(&inbox.update_policy(NotificationPolicy::default(), clock(1702)));
    let drop = inbox.receive_opened_from(
        &third,
        generation(1),
        &mut correlation(1800, 2),
        clock(1800),
    );
    assert_eq!(drop.issue(), Some(InboxIssue::GuardQuarantine));
    no_positive(&drop);
    no_positive(&inbox.observe_service_clock(&correlation(3000, 3), clock(3000)));
    assert_eq!(inbox.retained_count(), 0);
    let next = inbox.receive_opened_from(
        &opened(4, 3, 3000, 4000),
        generation(1),
        &mut correlation(3000, 3),
        clock(3000),
    );
    assert!(
        next.effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
    assert_eq!(
        inbox
            .receive_opened_from(
                &third,
                generation(1),
                &mut correlation(3001, 2),
                clock(3001)
            )
            .issue(),
        Some(InboxIssue::WrongEpoch)
    );
    let _ = saved(&inbox);
}

#[test]
fn active_off_hours_boundary_withdraws_once_and_later_renewal_cannot_restore_it() {
    let policy = NotificationPolicy::new(
        Some(Schedule::Weekly(
            WeeklySchedule::new(vec![TimeWindow::new(DayMask::ALL, 600, 601).unwrap()]).unwrap(),
        )),
        AlertMode::Silent,
    );
    let mut inbox = inbox(policy, CapacityLimits::default());
    let first = opened(1, 2, 0, 1000);
    let second = renewed(&first, 6, 900, 1900);
    let third = renewed(&second, 7, 1800, 2800);
    inbox.receive_opened_from(&first, generation(1), &mut correlation(0, 2), clock(0));
    let update = inbox.receive_opened_from(
        &second,
        generation(1),
        &mut correlation(900, 2),
        clock_at(900, 601),
    );
    no_positive(&update);
    assert!(
        update
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Withdraw { .. }))
    );
    let (mut inbox, _) =
        PhoneInbox::restore_checkpoint(saved(&inbox), boot(), clock_at(901, 601)).unwrap();
    no_positive(&inbox.update_policy(NotificationPolicy::default(), clock_at(902, 601)));
    no_positive(&inbox.receive_opened_from(
        &third,
        generation(1),
        &mut correlation(1800, 2),
        clock_at(1800, 601),
    ));
    assert_eq!(inbox.active_count(), 0);
    assert!(inbox.pending_outcomes().is_empty());
}

#[test]
fn expired_recovery_lease_cannot_be_extended_by_new_signed_request_lease() {
    let policy = NotificationPolicy::new(
        Some(Schedule::Weekly(
            WeeklySchedule::new(vec![TimeWindow::new(DayMask::ALL, 600, 602).unwrap()]).unwrap(),
        )),
        AlertMode::Silent,
    );
    let mut original = inbox(policy, CapacityLimits::default());
    let first = opened(1, 2, 0, 100_000);
    let second = renewed(&first, 6, 90_000, 190_000);
    original.receive_opened_from(&first, generation(1), &mut correlation(0, 2), clock(0));
    let (mut restored, update) =
        PhoneInbox::restore_checkpoint(saved(&original), boot(), clock_at(60_001, 601)).unwrap();
    no_positive(&update);
    assert_eq!(restored.recovering_count(), 0);
    no_positive(&restored.receive_opened_from(
        &second,
        generation(1),
        &mut correlation(90_000, 2),
        clock_at(90_000, 601),
    ));
    assert_eq!(restored.active_count(), 0);
    let _ = saved(&restored);
}

#[test]
fn acknowledged_old_expiry_does_not_remove_renewable_suppression() {
    let mut inbox = inbox(NotificationPolicy::default(), CapacityLimits::default());
    let first = opened(1, 2, 0, 1000);
    let second = renewed(&first, 6, 900, 1900);
    inbox.receive_opened_from(&first, generation(1), &mut correlation(0, 2), clock(0));
    inbox.poll(clock(1000));
    assert_eq!(inbox.pending_outcomes().len(), 1);
    no_positive(&inbox.receive_opened_from(
        &second,
        generation(1),
        &mut correlation(1100, 2),
        clock(1100),
    ));
    let _ = saved(&inbox);
    let id = inbox.pending_outcomes()[0].delivery_id();
    inbox.acknowledge_outcome(id);
    let (mut inbox, _) =
        PhoneInbox::restore_checkpoint(saved(&inbox), boot(), clock(1101)).unwrap();
    no_positive(&inbox.receive_opened_from(
        &second,
        generation(1),
        &mut correlation(1102, 2),
        clock(1102),
    ));
    no_positive(&inbox.resolve_pc_from(
        &final_event(&second),
        generation(1),
        &mut correlation(1103, 2),
        clock(1103),
    ));
    assert!(inbox.pending_outcomes().is_empty());
    no_positive(&inbox.observe_service_clock(&correlation(2000, 2), clock(2000)));
    assert_eq!(inbox.retained_count(), 0);
}
