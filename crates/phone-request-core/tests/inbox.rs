// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic keys and clocks only; no device, OS notifications or authorization.

use std::sync::{Arc, Weak};

use approval_protocol::{
    BootEpoch, ChallengeNonce, ExpiryTick, OsSession, PcIdentity, RequestBinding, RequestContent,
    RequestId,
};
use notification_policy::{
    DayMask, DropReason, RequestOutcome, Schedule, TimeWindow, Weekday, WeeklySchedule,
    WithdrawalReason,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use phone_request_core::{
    AlertMode, CapacityLimits, ClockReading, Effect, InboxClock, InboxFault, InboxIssue,
    InboxUpdate, LocalTime, MonotonicTime, NotificationPolicy, OutcomeAcknowledgment, PhoneInbox,
    RequestKey, request_key,
};
use service_protocol::{
    ClockCorrelation, ClockProbe, PcEvent, PcPublicKey, RequestResolution, ServiceTick,
    UnsignedPcEvent, VerifiedPcEvent,
};

const MILLI: u64 = 1_000_000;

fn pc(value: u8) -> PcIdentity {
    PcIdentity::from_bytes([value; 32]).expect("synthetic PC")
}
fn epoch(value: u8) -> BootEpoch {
    BootEpoch::from_bytes([value; 32]).expect("synthetic epoch")
}
fn request_id(value: u64) -> RequestId {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    RequestId::from_bytes(bytes).expect("synthetic nonzero request ID")
}

fn verified(event: PcEvent) -> VerifiedPcEvent {
    let expected_pc = event.pc();
    let key = SigningKey::from_slice(&[7; 32]).expect("public synthetic test key, never enrolled");
    let public =
        PcPublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
            .expect("synthetic public key");
    let unsigned = UnsignedPcEvent::new(event).expect("valid synthetic event");
    let signature: Signature = key.sign(&unsigned.signing_bytes());
    unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .expect("synthetic signature")
        .verify(expected_pc, &public)
        .expect("verified synthetic fixture")
}

fn correlation_for(
    peer: u8,
    boot: u8,
    sent_ms: u64,
    received_ms: u64,
    sample_ms: u64,
) -> ClockCorrelation {
    correlation_nanos(
        peer,
        boot,
        sent_ms * MILLI,
        received_ms * MILLI,
        sample_ms * MILLI,
    )
}

fn correlation_nanos(
    peer: u8,
    boot: u8,
    sent: u64,
    received: u64,
    sample: u64,
) -> ClockCorrelation {
    let probe = ClockProbe::start(pc(peer), sent).expect("fresh test probe");
    let response = verified(PcEvent::Clock {
        pc: pc(peer),
        epoch: epoch(boot),
        probe: probe.nonce(),
        sampled_at: ServiceTick::from_nanos_since_epoch(sample),
    });
    probe
        .complete(&response, received)
        .expect("synthetic correlation")
}

fn correlation() -> ClockCorrelation {
    correlation_for(1, 2, 0, 0, 0)
}

fn clock(ms: u64, minute: u16) -> InboxClock {
    clock_nanos(ms * MILLI, minute)
}
fn clock_nanos(nanos: u64, minute: u16) -> InboxClock {
    InboxClock::new(
        ClockReading::new(
            MonotonicTime::from_millis(nanos / MILLI),
            LocalTime::new(Weekday::Monday, minute).expect("synthetic local minute"),
        ),
        nanos,
    )
    .expect("coherent synthetic native observations")
}

fn opened_for(peer: u8, boot: u8, id: u64, issued_ms: u64, expiry_ms: u64) -> VerifiedPcEvent {
    let content = Arc::new(
        RequestContent::new(
            "합성 수신함 테스트 앱",
            "C:\\Synthetic\\inbox-fixture.exe",
            "synthetic inert request details",
        )
        .expect("inert synthetic content"),
    );
    opened_parts(
        peer,
        boot,
        id,
        issued_ms * MILLI,
        expiry_ms * MILLI,
        content,
    )
}

fn opened_parts(
    peer: u8,
    boot: u8,
    id: u64,
    issued_nanos: u64,
    expiry_nanos: u64,
    content: Arc<RequestContent>,
) -> VerifiedPcEvent {
    let binding = RequestBinding::new(
        pc(peer),
        epoch(boot),
        OsSession::new(1, 7),
        request_id(id),
        ChallengeNonce::from_bytes([5; 32]).expect("synthetic challenge"),
        content.digest(),
        ExpiryTick::from_nanos_since_epoch(expiry_nanos).expect("positive expiry"),
    );
    verified(PcEvent::Opened {
        binding,
        issued_at: ServiceTick::from_nanos_since_epoch(issued_nanos),
        content,
    })
}

fn opened(id: u64, issued_ms: u64, expiry_ms: u64) -> VerifiedPcEvent {
    opened_for(1, 2, id, issued_ms, expiry_ms)
}

fn serialized_checkpoint(inbox: &PhoneInbox) -> phone_request_core::InboxCheckpoint {
    let bytes = inbox.checkpoint().unwrap().to_bytes().unwrap();
    phone_request_core::InboxCheckpoint::from_bytes(&bytes).unwrap()
}

#[test]
fn checkpoint_keeps_an_off_hours_drop_but_admits_a_new_cold_start_request() {
    use phone_request_core::PhoneBootId;
    let boot = PhoneBootId::from_native_boot_count(7).unwrap();
    let policy = NotificationPolicy::new(
        Some(Schedule::Weekly(
            WeeklySchedule::new(vec![TimeWindow::new(DayMask::ALL, 600, 660).unwrap()]).unwrap(),
        )),
        AlertMode::Sound,
    );
    let mut original = PhoneInbox::with_phone_boot(policy, CapacityLimits::default(), boot);
    let mut first_clock = correlation();
    let discarded = opened(8001, 0, 10_000);
    let update = original.receive_opened(&discarded, &mut first_clock, clock(100, 599));
    assert!(update.effects().iter().any(|effect| matches!(
        effect,
        Effect::Drop {
            reason: DropReason::OutsideAllowedTime,
            ..
        }
    )));
    let checkpoint = original.checkpoint().unwrap();
    let bytes = checkpoint.to_bytes().unwrap();
    let checkpoint = phone_request_core::InboxCheckpoint::from_bytes(&bytes).unwrap();
    drop(original);
    let (mut restored, recovery) =
        PhoneInbox::restore_checkpoint(checkpoint, boot, clock(200, 600)).unwrap();
    assert!(
        !recovery
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_) | Effect::Restore(_)))
    );
    assert_eq!(restored.retained_body_count(), 0);
    let mut fresh_clock = correlation_for(1, 2, 200, 200, 200);
    let replay = restored.receive_opened(&discarded, &mut fresh_clock, clock(201, 600));
    assert!(!replay.effects().iter().any(|effect| matches!(
        effect,
        Effect::Show(_) | Effect::Restore(_) | Effect::RecordOutcome { .. }
    )));
    assert!(
        restored
            .check_pending(key(&discarded), clock(202, 600))
            .request()
            .is_none()
    );
    // This request predates the new clock probe: it can be the push that woke
    // the cold process. It was never discarded, so it must not hit a cutoff.
    let new_request = opened(8002, 150, 10_000);
    let received = restored.receive_opened(&new_request, &mut fresh_clock, clock(203, 600));
    assert!(
        received
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
}

#[test]
fn same_boot_active_recovery_needs_a_reverified_body_and_never_extends_expiry() {
    use phone_request_core::PhoneBootId;
    let boot = PhoneBootId::from_native_boot_count(7).unwrap();
    let mut original = PhoneInbox::with_phone_boot(
        NotificationPolicy::default(),
        CapacityLimits::default(),
        boot,
    );
    let event = opened(8003, 0, 1_000);
    let weak = body_weak(&event);
    original.receive_opened(&event, &mut correlation(), clock(1, 600));
    let saved = serialized_checkpoint(&original);
    drop(original);
    drop(event);
    assert!(
        weak.upgrade().is_none(),
        "checkpoint must never retain the original body"
    );
    let (mut restored, _) = PhoneInbox::restore_checkpoint(saved, boot, clock(200, 600)).unwrap();
    assert_eq!(restored.recovering_count(), 1);
    let checked = restored.check_pending(
        request_key(binding(&opened(8003, 0, 1_000))),
        clock(200, 600),
    );
    assert!(checked.request().is_none());
    assert_eq!(checked.update().fault(), None);
    let reverified = opened(8003, 0, 1_000);
    let mut newer = correlation_for(1, 2, 200, 200, 50);
    let update = restored.receive_opened(&reverified, &mut newer, clock(201, 600));
    assert!(
        matches!(update.effects(), [Effect::Restore(pending)] if pending.expires_at.as_millis() == 1_000)
    );
    assert_eq!(restored.recovering_count(), 0);
    assert!(
        restored
            .check_pending(key(&reverified), clock(999, 600))
            .request()
            .is_some()
    );
    let expired = restored.check_pending(key(&reverified), clock(1_000, 600));
    assert!(expired.request().is_none());
    assert!(expired.update().effects().iter().any(|effect| matches!(
        effect,
        Effect::RecordOutcome {
            outcome: RequestOutcome::ExpiredLocally,
            ..
        }
    )));
}

#[test]
fn a_new_phone_boot_never_reuses_old_mappings_but_accepts_unseen_requests() {
    use phone_request_core::PhoneBootId;
    let old_boot = PhoneBootId::from_native_boot_count(7).unwrap();
    let new_boot = PhoneBootId::from_native_boot_count(8).unwrap();
    let mut original = PhoneInbox::with_phone_boot(
        NotificationPolicy::default(),
        CapacityLimits::default(),
        old_boot,
    );
    let seen = opened(8004, 0, 10_000);
    original.receive_opened(&seen, &mut correlation(), clock(5_000, 600));
    let (mut restored, _) =
        PhoneInbox::restore_checkpoint(serialized_checkpoint(&original), new_boot, clock(1, 600))
            .unwrap();
    assert_eq!(restored.recovering_count(), 0);
    let mut new_clock = correlation_for(1, 2, 1, 1, 5_001);
    let replay = restored.receive_opened(&seen, &mut new_clock, clock(2, 600));
    assert!(replay.effects().iter().all(|effect| !matches!(
        effect,
        Effect::Show(_) | Effect::Restore(_) | Effect::RecordOutcome { .. }
    )));
    let fresh = opened(8005, 5_000, 10_000);
    let arrived = restored.receive_opened(&fresh, &mut new_clock, clock(3, 600));
    assert!(
        arrived
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
}

#[test]
fn recovery_lease_can_suppress_old_metadata_without_suppressing_a_new_request() {
    use phone_request_core::PhoneBootId;
    let boot = PhoneBootId::from_native_boot_count(7).unwrap();
    let mut original = PhoneInbox::with_phone_boot(
        weekly(600, 601, AlertMode::Sound),
        CapacityLimits::default(),
        boot,
    );
    let seen = opened(8006, 0, 120_000);
    original.receive_opened(&seen, &mut correlation(), clock(1, 600));
    let (mut restored, update) =
        PhoneInbox::restore_checkpoint(serialized_checkpoint(&original), boot, clock(2, 600))
            .unwrap();
    assert!(update.effects().iter().any(|effect| matches!(
        effect,
        Effect::Withdraw {
            reason: WithdrawalReason::RecoveryRejected,
            ..
        }
    )));
    assert!(
        update
            .effects()
            .iter()
            .all(|effect| !matches!(effect, Effect::RecordOutcome { .. }))
    );
    assert_eq!(restored.recovering_count(), 0);
    let replay = restored.receive_opened(&seen, &mut correlation(), clock(3, 600));
    assert!(
        replay
            .effects()
            .iter()
            .all(|effect| !matches!(effect, Effect::Show(_) | Effect::Restore(_)))
    );
    let fresh = opened(8007, 0, 120_000);
    assert!(
        restored
            .receive_opened(&fresh, &mut correlation(), clock(4, 600))
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
}

#[test]
fn checkpoint_codec_is_bounded_body_free_and_rejects_every_partial_record() {
    use phone_request_core::{InboxCheckpoint, InboxCheckpointError, PhoneBootId};
    let boot = PhoneBootId::from_native_boot_count(0).unwrap();
    let mut state = PhoneInbox::with_phone_boot(
        NotificationPolicy::default(),
        CapacityLimits::default(),
        boot,
    );
    let event = opened(8_008, 0, 10_000);
    state.receive_opened(&event, &mut correlation(), clock(1, 600));
    let bytes = state.checkpoint().unwrap().to_bytes().unwrap();
    for needle in [
        "합성 수신함 테스트 앱",
        "C:\\Synthetic\\inbox-fixture.exe",
        "synthetic inert request details",
    ] {
        assert!(
            !bytes
                .windows(needle.len())
                .any(|window| window == needle.as_bytes())
        );
    }
    for length in 0..bytes.len() {
        assert!(
            InboxCheckpoint::from_bytes(&bytes[..length]).is_err(),
            "prefix {length}"
        );
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(InboxCheckpoint::from_bytes(&extra).is_err());
    let mut bad_version = bytes.clone();
    bad_version[9] = 3;
    assert_eq!(
        InboxCheckpoint::from_bytes(&bad_version).unwrap_err(),
        InboxCheckpointError::UnsupportedVersion
    );
    let mut bad_boot = bytes.clone();
    bad_boot[10..14].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(InboxCheckpoint::from_bytes(&bad_boot).is_err());
    let mut bad_capacity = bytes.clone();
    bad_capacity[14..16].copy_from_slice(&0_u16.to_be_bytes());
    assert!(InboxCheckpoint::from_bytes(&bad_capacity).is_err());
    assert_eq!(
        InboxCheckpoint::from_bytes(&vec![0; 384 * 1024 + 1]).unwrap_err(),
        InboxCheckpointError::TooLarge
    );
}

#[test]
fn source_expiry_and_owner_fault_withdraw_recovering_ids_without_a_body() {
    use phone_request_core::PhoneBootId;
    let boot = PhoneBootId::from_native_boot_count(7).unwrap();
    let mut original = PhoneInbox::with_phone_boot(
        NotificationPolicy::default(),
        CapacityLimits::default(),
        boot,
    );
    let event = opened(8_009, 0, 1_000);
    original.receive_opened(&event, &mut correlation(), clock(1, 600));
    let checkpoint = serialized_checkpoint(&original);
    let (mut restored, _) =
        PhoneInbox::restore_checkpoint(checkpoint.clone(), boot, clock(2, 600)).unwrap();
    let expired =
        restored.observe_service_clock(&correlation_for(1, 2, 2, 2, 1_000), clock(3, 600));
    assert!(expired.effects().iter().any(|effect| matches!(
        effect,
        Effect::RecordOutcome {
            outcome: RequestOutcome::ExpiredByPc,
            ..
        }
    )));
    assert_eq!(restored.recovering_count(), 0);
    serialized_checkpoint(&restored);
    let (mut failed, _) = PhoneInbox::restore_checkpoint(checkpoint, boot, clock(2, 600)).unwrap();
    let stopped = failed.stop_for_owner_failure();
    assert!(stopped.effects().iter().any(|effect| matches!(
        effect,
        Effect::Withdraw {
            reason: WithdrawalReason::EngineFault,
            ..
        }
    )));
    assert_eq!(failed.recovering_count(), 0);
    let (faulted_reopen, _) = PhoneInbox::restore_checkpoint(
        serialized_checkpoint(&failed),
        PhoneBootId::from_native_boot_count(8).unwrap(),
        clock(0, 600),
    )
    .unwrap();
    assert!(faulted_reopen.fault().is_some());
    serialized_checkpoint(&faulted_reopen);
}

#[test]
fn same_phone_boot_rejects_native_regression_instead_of_resetting_observations() {
    use phone_request_core::{InboxCheckpointError, PhoneBootId};
    let boot = PhoneBootId::from_native_boot_count(7).unwrap();
    let mut original = PhoneInbox::with_phone_boot(
        NotificationPolicy::default(),
        CapacityLimits::default(),
        boot,
    );
    original.poll(clock(100, 600));
    assert_eq!(
        PhoneInbox::restore_checkpoint(serialized_checkpoint(&original), boot, clock(99, 600))
            .unwrap_err(),
        InboxCheckpointError::ClockRegressed
    );
    assert_eq!(
        PhoneInbox::new(NotificationPolicy::default(), CapacityLimits::default())
            .checkpoint()
            .unwrap_err(),
        InboxCheckpointError::MissingBoot
    );
    assert!(PhoneBootId::from_native_boot_count(u32::MAX).is_err());
}

#[test]
fn an_unobserved_owner_failure_can_be_checkpointed_without_inventing_a_clock() {
    use phone_request_core::PhoneBootId;
    let boot = PhoneBootId::from_native_boot_count(7).unwrap();
    let mut state = PhoneInbox::with_phone_boot(
        NotificationPolicy::default(),
        CapacityLimits::default(),
        boot,
    );
    state.stop_for_owner_failure();
    let saved = serialized_checkpoint(&state);
    let (restored, update) = PhoneInbox::restore_checkpoint(saved, boot, clock(1, 600)).unwrap();
    assert_eq!(restored.fault(), Some(InboxFault::ReceivingOwnerStopped));
    assert!(update.effects().is_empty());
}

#[test]
fn a_detectable_local_clock_jump_blocks_only_old_recovery_not_a_new_request() {
    use phone_request_core::PhoneBootId;
    let boot = PhoneBootId::from_native_boot_count(7).unwrap();
    let policy = NotificationPolicy::new(
        Some(Schedule::Weekly(
            WeeklySchedule::new(vec![
                TimeWindow::new(DayMask::ALL, 600, 602).unwrap(),
                TimeWindow::new(DayMask::ALL, 660, 662).unwrap(),
            ])
            .unwrap(),
        )),
        AlertMode::Sound,
    );
    let mut original = PhoneInbox::with_phone_boot(policy, CapacityLimits::default(), boot);
    let seen = opened(8_010, 0, 120_000);
    original.receive_opened(&seen, &mut correlation(), clock(100, 600));
    let (mut restored, _) =
        PhoneInbox::restore_checkpoint(serialized_checkpoint(&original), boot, clock(200, 660))
            .unwrap();
    let update = restored.receive_opened(&seen, &mut correlation(), clock(201, 660));
    assert!(
        update
            .effects()
            .iter()
            .all(|effect| !matches!(effect, Effect::Show(_) | Effect::Restore(_)))
    );
    let fresh = opened(8_011, 0, 120_000);
    assert!(
        restored
            .receive_opened(&fresh, &mut correlation(), clock(202, 660))
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
}

fn active_checkpoint_bytes() -> Vec<u8> {
    let boot = phone_request_core::PhoneBootId::from_native_boot_count(7).unwrap();
    let mut state = PhoneInbox::with_phone_boot(
        weekly(600, 660, AlertMode::Sound),
        CapacityLimits::default(),
        boot,
    );
    state.receive_opened(
        &opened(8_012, 0, 1_000),
        &mut correlation(),
        clock(100, 600),
    );
    state.checkpoint().unwrap().to_bytes().unwrap()
}

fn after_checkpoint_policy(bytes: &[u8]) -> usize {
    // Version-one fixed header and length-prefixed canonical policy field.
    22 + u32::from_be_bytes(bytes[18..22].try_into().unwrap()) as usize
}

#[test]
fn checkpoint_decoder_rejects_active_state_outside_its_saved_policy_observation() {
    let mut bytes = active_checkpoint_bytes();
    let clock_start = after_checkpoint_policy(&bytes);
    bytes[clock_start + 11..clock_start + 13].copy_from_slice(&599_u16.to_be_bytes());
    assert!(phone_request_core::InboxCheckpoint::from_bytes(&bytes).is_err());
}

#[test]
fn checkpoint_decoder_rejects_a_nested_time_only_quarantine_without_source_barriers() {
    let mut bytes = active_checkpoint_bytes();
    let clock_start = after_checkpoint_policy(&bytes);
    assert_eq!(bytes[clock_start + 25], 0);
    bytes[clock_start + 25] = 1;
    bytes.splice(clock_start + 26..clock_start + 26, 500_u64.to_be_bytes());
    assert!(phone_request_core::InboxCheckpoint::from_bytes(&bytes).is_err());
}

#[test]
fn checkpoint_decoder_rejects_an_original_issue_in_the_saved_submillisecond_future() {
    let boot = phone_request_core::PhoneBootId::from_native_boot_count(7).unwrap();
    let mut state = PhoneInbox::with_phone_boot(
        NotificationPolicy::default(),
        CapacityLimits::default(),
        boot,
    );
    let content =
        Arc::new(RequestContent::new("Synthetic", "C:\\Synthetic\\app.exe", "inert").unwrap());
    let event = opened_parts(1, 2, 8_013, 100_500_000, 1_000_000_000, content);
    state.receive_opened(&event, &mut correlation(), clock_nanos(100_500_100, 600));
    let mut bytes = state.checkpoint().unwrap().to_bytes().unwrap();
    let clock_start = after_checkpoint_policy(&bytes);
    bytes[clock_start + 1..clock_start + 9].copy_from_slice(&100_499_999_u64.to_be_bytes());
    assert!(phone_request_core::InboxCheckpoint::from_bytes(&bytes).is_err());
}

fn binding(event: &VerifiedPcEvent) -> RequestBinding {
    match event.event() {
        PcEvent::Opened { binding, .. } | PcEvent::Resolved { binding, .. } => *binding,
        PcEvent::Clock { .. } => panic!("fixture must be a request"),
    }
}

fn key(event: &VerifiedPcEvent) -> RequestKey {
    request_key(binding(event))
}

fn resolution(event: &VerifiedPcEvent, outcome: RequestResolution) -> VerifiedPcEvent {
    let (binding, issued_at) = match event.event() {
        PcEvent::Opened {
            binding, issued_at, ..
        }
        | PcEvent::Resolved {
            binding, issued_at, ..
        } => (*binding, *issued_at),
        PcEvent::Clock { .. } => panic!("fixture must be a request"),
    };
    verified(PcEvent::Resolved {
        binding,
        issued_at,
        outcome,
    })
}

fn weekly(start: u16, end: u16, alert: AlertMode) -> NotificationPolicy {
    NotificationPolicy::new(
        Some(Schedule::Weekly(
            WeeklySchedule::new([
                TimeWindow::new(DayMask::new(1).expect("Monday"), start, end).expect("window"),
            ])
            .expect("weekly schedule"),
        )),
        alert,
    )
}

fn inbox() -> PhoneInbox {
    PhoneInbox::new(NotificationPolicy::default(), CapacityLimits::default())
}
fn no_show_or_history(update: &InboxUpdate) {
    assert!(
        !update
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_) | Effect::RecordOutcome { .. }))
    );
}
fn has_drop(update: &InboxUpdate, expected_key: RequestKey, expected_reason: DropReason) -> bool {
    update.effects().contains(&Effect::Drop {
        key: expected_key,
        reason: expected_reason,
    })
}
fn body_weak(event: &VerifiedPcEvent) -> Weak<RequestContent> {
    let PcEvent::Opened { content, .. } = event.event() else {
        panic!("opened fixture")
    };
    Arc::downgrade(content)
}

#[test]
fn default_allows_sound_and_body_is_readable_only_through_current_check() {
    let mut inbox = inbox();
    let mut correlation = correlation();
    let event = opened(1, 0, 1_000);
    let update = inbox.receive_opened(&event, &mut correlation, clock(1, 600));
    assert!(
        matches!(update.effects(), [Effect::Show(pending)] if pending.alert == AlertMode::Sound)
    );
    assert_eq!(update.issue(), None);
    assert_eq!(inbox.active_count(), 1);
    assert_eq!(inbox.retained_count(), 1);
    let checked = inbox.check_pending(key(&event), clock(2, 600));
    let view = checked.request().expect("current active request");
    assert_eq!(view.binding(), binding(&event));
    assert_eq!(view.content().program_name(), "합성 수신함 테스트 앱");
    assert_eq!(
        view.notification().expires_at,
        MonotonicTime::from_millis(1_000)
    );
    assert_eq!(inbox.next_deadline_nanos(), Some(1_000 * MILLI));
}

#[test]
fn off_hours_drops_body_and_does_not_reappear_in_later_allowed_time() {
    let mut inbox = PhoneInbox::new(
        weekly(600, 660, AlertMode::Sound),
        CapacityLimits::default(),
    );
    let mut correlation = correlation();
    let event = opened(1, 0, 120_000);
    let weak = body_weak(&event);
    assert_eq!(weak.strong_count(), 1);
    let dropped = inbox.receive_opened(&event, &mut correlation, clock(1, 599));
    assert!(has_drop(
        &dropped,
        key(&event),
        DropReason::OutsideAllowedTime
    ));
    no_show_or_history(&dropped);
    assert_eq!(inbox.retained_body_count(), 0);
    assert_eq!(weak.strong_count(), 1);
    let retry = inbox.receive_opened(&event, &mut correlation, clock(60_001, 600));
    assert!(has_drop(
        &retry,
        key(&event),
        DropReason::PreviouslySuppressed
    ));
    no_show_or_history(&retry);
    assert!(
        inbox
            .check_pending(key(&event), clock(60_002, 600))
            .request()
            .is_none()
    );
    assert_eq!(inbox.retained_count(), 1);
    drop(event);
    assert!(weak.upgrade().is_none());
}

#[test]
fn silent_and_vibrate_are_preserved_and_changes_update_without_renotifying() {
    for mode in [AlertMode::Silent, AlertMode::VibrateOnly] {
        let mut inbox = PhoneInbox::new(
            NotificationPolicy::new(None, mode),
            CapacityLimits::default(),
        );
        let mut correlation = correlation();
        let event = opened(1, 0, 1_000);
        let shown = inbox.receive_opened(&event, &mut correlation, clock(1, 600));
        assert!(matches!(shown.effects(), [Effect::Show(pending)] if pending.alert == mode));
        let changed = inbox.update_policy(NotificationPolicy::default(), clock(2, 600));
        assert_eq!(
            changed.effects(),
            [Effect::UpdateAlert {
                key: key(&event),
                alert: AlertMode::Sound
            }]
        );
        no_show_or_history(&changed);
        assert_eq!(
            inbox
                .check_pending(key(&event), clock(3, 600))
                .request()
                .expect("still active")
                .notification()
                .alert,
            AlertMode::Sound
        );
    }
}

#[test]
fn schedule_change_releases_body_without_history_and_expansion_cannot_restore_it() {
    let mut inbox = inbox();
    let mut correlation = correlation();
    let event = opened(1, 0, 1_000);
    let weak = body_weak(&event);
    inbox.receive_opened(&event, &mut correlation, clock(1, 600));
    assert_eq!(weak.strong_count(), 2);
    let changed = inbox.update_policy(weekly(660, 720, AlertMode::Sound), clock(2, 600));
    assert_eq!(
        changed.effects(),
        [Effect::Withdraw {
            key: key(&event),
            reason: WithdrawalReason::ScheduleBlocked
        }]
    );
    no_show_or_history(&changed);
    assert_eq!(weak.strong_count(), 1);
    assert_eq!(inbox.retained_body_count(), 0);
    no_show_or_history(&inbox.update_policy(NotificationPolicy::default(), clock(3, 600)));
    let retry = inbox.receive_opened(&event, &mut correlation, clock(4, 600));
    assert!(has_drop(
        &retry,
        key(&event),
        DropReason::PreviouslySuppressed
    ));
    assert!(
        inbox
            .check_pending(key(&event), clock(5, 600))
            .request()
            .is_none()
    );
}

#[test]
fn explicit_never_drops_without_a_body_or_user_history() {
    let mut inbox = PhoneInbox::new(
        NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent),
        CapacityLimits::default(),
    );
    let mut correlation = correlation();
    let event = opened(1, 0, 1_000);
    let update = inbox.receive_opened(&event, &mut correlation, clock(1, 600));
    assert!(has_drop(
        &update,
        key(&event),
        DropReason::NotificationsDisabled
    ));
    no_show_or_history(&update);
    assert_eq!(inbox.retained_count(), 1);
    assert_eq!(inbox.retained_body_count(), 0);
}

#[test]
fn fresh_probe_never_replaces_the_original_window_or_revives_a_retired_guard() {
    let mut inbox = inbox();
    let mut original = correlation_for(1, 2, 1_000, 1_010, 5_000);
    let event = opened(1, 5_000, 6_000);
    inbox.receive_opened(&event, &mut original, clock(1_020, 600));
    let first = inbox
        .check_pending(key(&event), clock(1_021, 600))
        .request()
        .expect("first view")
        .original_window();
    assert_eq!(first.phone_expiry_nanos(), 2_000 * MILLI);
    let mut newer = correlation_for(1, 2, 1_050, 1_050, 5_040);
    let retry = inbox.receive_opened(&event, &mut newer, clock(1_060, 600));
    assert!(has_drop(&retry, key(&event), DropReason::DuplicateActive));
    let current = inbox.check_pending(key(&event), clock(1_061, 600));
    assert_eq!(
        current
            .request()
            .expect("same original window")
            .original_window(),
        first
    );
    drop(current);
    let expired = inbox.poll(clock(2_000, 600));
    assert!(expired.effects().contains(&Effect::RecordOutcome {
        key: key(&event),
        outcome: RequestOutcome::ExpiredLocally
    }));
    assert_eq!(inbox.retained_body_count(), 0);
    assert_eq!(
        inbox.retained_count(),
        1,
        "original upper guard survives lower expiry"
    );
    let retired_retry = inbox.receive_opened(&event, &mut newer, clock(2_005, 600));
    assert!(has_drop(&retired_retry, key(&event), DropReason::Expired));
    no_show_or_history(&retired_retry);
    assert_eq!(inbox.retained_count(), 1);
    inbox.poll(clock(2_010, 600));
    assert_eq!(
        inbox.retained_count(),
        1,
        "phone upper alone is not source-expiry proof"
    );
    let confirmed = correlation_for(1, 2, 2_010, 2_010, 6_000);
    no_show_or_history(&inbox.observe_service_clock(&confirmed, clock(2_010, 600)));
    assert_eq!(
        inbox.retained_count(),
        0,
        "original phone upper and authenticated source expiry permit guard removal"
    );
    let old_retry = inbox.receive_opened(&event, &mut newer, clock(2_010, 600));
    no_show_or_history(&old_retry);
    assert!(has_drop(&old_retry, key(&event), DropReason::Expired));
}

#[test]
fn off_hours_guard_survives_lower_expiry_and_a_later_more_favorable_probe() {
    let mut inbox = PhoneInbox::new(
        weekly(660, 720, AlertMode::Sound),
        CapacityLimits::default(),
    );
    let mut original = correlation_for(1, 2, 1_000, 1_010, 5_000);
    let event = opened(1, 5_000, 6_000);
    inbox.receive_opened(&event, &mut original, clock(1_020, 600));
    inbox.update_policy(NotificationPolicy::default(), clock(2_000, 600));
    let mut newer = correlation_for(1, 2, 2_001, 2_001, 5_991);
    let retry = inbox.receive_opened(&event, &mut newer, clock(2_005, 600));
    no_show_or_history(&retry);
    assert!(
        inbox
            .check_pending(key(&event), clock(2_006, 600))
            .request()
            .is_none()
    );
    assert_eq!(inbox.retained_count(), 1);
    assert_eq!(inbox.retained_body_count(), 0);
}

#[test]
fn conflicting_full_binding_or_original_submillisecond_issuance_cannot_replace_body() {
    let mut inbox = inbox();
    let mut correlation = correlation();
    let original = opened(1, 0, 1_000);
    inbox.receive_opened(&original, &mut correlation, clock(1, 600));
    let PcEvent::Opened {
        binding: old,
        content,
        ..
    } = original.event()
    else {
        unreachable!()
    };
    let changed_binding = RequestBinding::new(
        old.pc(),
        old.epoch(),
        old.session(),
        old.request_id(),
        ChallengeNonce::from_bytes([9; 32]).expect("different synthetic challenge"),
        old.content_digest(),
        old.expiry(),
    );
    let changed = verified(PcEvent::Opened {
        binding: changed_binding,
        issued_at: ServiceTick::from_nanos_since_epoch(0),
        content: Arc::clone(content),
    });
    let rejected = inbox.receive_opened(&changed, &mut correlation, clock(2, 600));
    assert_eq!(rejected.issue(), Some(InboxIssue::ConflictingBinding));
    no_show_or_history(&rejected);
    let changed_issuance = verified(PcEvent::Resolved {
        binding: *old,
        issued_at: ServiceTick::from_nanos_since_epoch(1),
        outcome: RequestResolution::Cancelled,
    });
    let rejected = inbox.resolve_pc(&changed_issuance, &mut correlation, clock(3, 600));
    assert_eq!(rejected.issue(), Some(InboxIssue::ConflictingIssuedAt));
    no_show_or_history(&rejected);
    assert_eq!(
        inbox
            .check_pending(key(&original), clock(4, 600))
            .request()
            .expect("original still active")
            .binding(),
        *old
    );
}

#[test]
fn separately_signed_changed_content_digest_is_still_a_binding_conflict() {
    let mut inbox = inbox();
    let mut correlation = correlation();
    let original = opened(1, 0, 1_000);
    inbox.receive_opened(&original, &mut correlation, clock(1, 600));
    let changed_content = Arc::new(
        RequestContent::new(
            "다른 합성 앱",
            "C:\\Synthetic\\other.exe",
            "different synthetic body",
        )
        .expect("fixture"),
    );
    let changed = opened_parts(1, 2, 1, 0, 1_000 * MILLI, changed_content);
    assert_eq!(
        inbox
            .receive_opened(&changed, &mut correlation, clock(2, 600))
            .issue(),
        Some(InboxIssue::ConflictingBinding)
    );
    assert_eq!(
        inbox
            .check_pending(key(&original), clock(3, 600))
            .request()
            .expect("original body")
            .content()
            .program_name(),
        "합성 수신함 테스트 앱"
    );
}

#[test]
fn signed_resolution_before_open_prevents_resurrection_without_history() {
    let mut inbox = inbox();
    let mut correlation = correlation();
    let original = opened(1, 0, 1_000);
    let closed = resolution(&original, RequestResolution::Cancelled);
    let first = inbox.resolve_pc(&closed, &mut correlation, clock(1, 600));
    assert!(has_drop(
        &first,
        key(&original),
        DropReason::ResolutionBeforeDelivery
    ));
    no_show_or_history(&first);
    let retry = inbox.receive_opened(&original, &mut correlation, clock(2, 600));
    assert!(has_drop(
        &retry,
        key(&original),
        DropReason::PreviouslySuppressed
    ));
    no_show_or_history(&retry);
    assert_eq!(inbox.retained_body_count(), 0);
    assert!(
        inbox
            .check_pending(key(&original), clock(3, 600))
            .request()
            .is_none()
    );
}

#[test]
fn unknown_resolution_after_lower_expiry_retains_a_body_free_upper_guard() {
    let mut inbox = inbox();
    let mut original = correlation_for(1, 2, 0, 10, 0);
    let event = opened(1, 0, 1_000);
    let closed = resolution(&event, RequestResolution::Expired);
    let dropped = inbox.resolve_pc(&closed, &mut original, clock(1_005, 600));
    no_show_or_history(&dropped);
    assert!(has_drop(&dropped, key(&event), DropReason::Expired));
    assert_eq!(inbox.retained_count(), 1);
    assert_eq!(inbox.retained_body_count(), 0);
    let mut newer = correlation_for(1, 2, 1_006, 1_006, 996);
    let retry = inbox.receive_opened(&event, &mut newer, clock(1_007, 600));
    no_show_or_history(&retry);
    assert!(
        inbox
            .check_pending(key(&event), clock(1_008, 600))
            .request()
            .is_none()
    );
}

#[test]
fn unknown_ancient_resolution_is_dropped_without_body_notification_or_history() {
    let mut inbox = inbox();
    let mut correlation = correlation_for(1, 2, 0, 10, 1_000);
    let event = opened(1, 0, 10);
    let update = inbox.resolve_pc(
        &resolution(&event, RequestResolution::Cancelled),
        &mut correlation,
        clock(20, 600),
    );
    no_show_or_history(&update);
    assert_eq!(inbox.retained_count(), 0);
    assert_eq!(inbox.retained_body_count(), 0);
    assert!(has_drop(&update, key(&event), DropReason::Expired));
}

#[test]
fn known_expired_resolution_does_not_need_a_fresh_live_clock_mapping() {
    let mut inbox = inbox();
    let mut correlation = correlation_for(1, 2, 0, 10, 0);
    let event = opened(1, 180_000, 300_000);
    inbox.receive_opened(&event, &mut correlation, clock(299_999, 600));
    // At this point map_request would reject the >5-minute correlation and the
    // expired lower window. Existing metadata must still drive expiry exactly once.
    let closed = resolution(&event, RequestResolution::Expired);
    let result = inbox.resolve_pc(&closed, &mut correlation, clock(300_005, 600));
    assert_eq!(result.issue(), None);
    assert_eq!(
        result
            .effects()
            .iter()
            .filter(|effect| matches!(effect, Effect::RecordOutcome { .. }))
            .count(),
        1
    );
    assert!(result.effects().contains(&Effect::RecordOutcome {
        key: key(&event),
        outcome: RequestOutcome::ExpiredLocally
    }));
    assert_eq!(inbox.retained_body_count(), 0);
    no_show_or_history(&inbox.resolve_pc(&closed, &mut correlation, clock(300_006, 600)));
}

#[test]
fn each_pc_terminal_resolution_produces_one_outcome_only_for_active_requests() {
    for (resolution_kind, expected) in [
        (RequestResolution::Cancelled, RequestOutcome::CancelledByPc),
        (RequestResolution::Expired, RequestOutcome::ExpiredByPc),
        (RequestResolution::Approved, RequestOutcome::CompletedByPc),
        (RequestResolution::Denied, RequestOutcome::CompletedByPc),
        (RequestResolution::Failed, RequestOutcome::CompletedByPc),
    ] {
        let mut inbox = inbox();
        let mut correlation = correlation();
        let event = opened(1, 0, 100);
        inbox.receive_opened(&event, &mut correlation, clock(1, 600));
        let closed = resolution(&event, resolution_kind);
        let result = inbox.resolve_pc(&closed, &mut correlation, clock(2, 600));
        assert!(result.effects().contains(&Effect::RecordOutcome {
            key: key(&event),
            outcome: expected
        }));
        assert_eq!(
            result
                .effects()
                .iter()
                .filter(|effect| matches!(effect, Effect::RecordOutcome { .. }))
                .count(),
            1
        );
        assert_eq!(inbox.retained_body_count(), 0);
        no_show_or_history(&inbox.resolve_pc(&closed, &mut correlation, clock(3, 600)));
        no_show_or_history(&inbox.poll(clock(100, 600)));
    }
}

#[test]
fn expiry_floors_nanoseconds_and_never_rounds_up_a_fractional_millisecond() {
    let mut inbox = inbox();
    let mut correlation = correlation();
    let content = Arc::new(
        RequestContent::new("합성", "C:\\Synthetic\\fraction.exe", "fixture").expect("content"),
    );
    let event = opened_parts(1, 2, 1, 0, 2 * MILLI + 999_999, content);
    inbox.receive_opened(&event, &mut correlation, clock(1, 600));
    let view = inbox.check_pending(key(&event), clock_nanos(MILLI + 500_000, 600));
    assert_eq!(
        view.request()
            .expect("before floored deadline")
            .notification()
            .expires_at
            .as_millis(),
        2
    );
    drop(view);
    let at_expiry = inbox.poll(clock(2, 600));
    assert!(at_expiry.effects().contains(&Effect::RecordOutcome {
        key: key(&event),
        outcome: RequestOutcome::ExpiredLocally
    }));
    assert_eq!(inbox.retained_body_count(), 0);
    assert_eq!(
        inbox.retained_count(),
        1,
        "fractional original upper still guarded"
    );
    assert!(
        inbox
            .check_pending(key(&event), clock_nanos(2 * MILLI + 1, 600))
            .request()
            .is_none()
    );
}

#[test]
fn submillisecond_window_is_conservatively_dropped_and_guarded() {
    let mut inbox = inbox();
    let mut correlation = correlation();
    let content = Arc::new(
        RequestContent::new("합성", "C:\\Synthetic\\small.exe", "fixture").expect("content"),
    );
    let event = opened_parts(1, 2, 1, 0, 999_999, content);
    let result = inbox.receive_opened(&event, &mut correlation, clock_nanos(1, 600));
    no_show_or_history(&result);
    assert!(has_drop(&result, key(&event), DropReason::Expired));
    assert_eq!(inbox.retained_body_count(), 0);
    assert_eq!(inbox.retained_count(), 1);
}

#[test]
fn active_capacity_drop_has_a_guard_and_does_not_fill_a_later_free_slot() {
    let mut inbox = PhoneInbox::new(
        NotificationPolicy::default(),
        CapacityLimits::new(1, 3).expect("limits"),
    );
    let mut correlation = correlation();
    let first = opened(1, 0, 1_000);
    let dropped = opened(2, 0, 1_000);
    inbox.receive_opened(&first, &mut correlation, clock(1, 600));
    let full = inbox.receive_opened(&dropped, &mut correlation, clock(2, 600));
    assert!(has_drop(&full, key(&dropped), DropReason::ActiveCapacity));
    assert_eq!(inbox.retained_count(), 2);
    assert_eq!(inbox.retained_body_count(), 1);
    inbox.resolve_pc(
        &resolution(&first, RequestResolution::Cancelled),
        &mut correlation,
        clock(3, 600),
    );
    let retry = inbox.receive_opened(&dropped, &mut correlation, clock(4, 600));
    no_show_or_history(&retry);
    assert!(has_drop(
        &retry,
        key(&dropped),
        DropReason::PreviouslySuppressed
    ));
    assert_eq!(inbox.retained_body_count(), 0);
}

#[test]
fn retired_guard_uses_the_same_capacity_budget_and_quarantines_untracked_requests() {
    let mut inbox = PhoneInbox::new(
        NotificationPolicy::default(),
        CapacityLimits::new(1, 1).expect("limits"),
    );
    let mut correlation = correlation_for(1, 2, 0, 10, 0);
    let first = opened(1, 0, 100);
    inbox.receive_opened(&first, &mut correlation, clock(11, 600));
    inbox.poll(clock(100, 600));
    assert_eq!(inbox.retained_body_count(), 0);
    assert_eq!(
        inbox.retained_count(),
        1,
        "upper guard still occupies the only slot"
    );
    let untracked = opened(2, 100, 200);
    let rejected = inbox.receive_opened(&untracked, &mut correlation, clock(100, 600));
    assert_eq!(rejected.issue(), Some(InboxIssue::GuardCapacity));
    assert_eq!(inbox.quarantine_until_nanos(), Some(210 * MILLI));
    inbox.poll(clock(110, 600));
    assert_eq!(inbox.retained_count(), 1);
    let first_expired = correlation_for(1, 2, 110, 110, 100);
    no_show_or_history(&inbox.observe_service_clock(&first_expired, clock(110, 600)));
    assert_eq!(inbox.retained_count(), 0);
    let retry = inbox.receive_opened(&untracked, &mut correlation, clock(111, 600));
    assert_eq!(retry.issue(), Some(InboxIssue::GuardQuarantine));
    no_show_or_history(&retry);
    inbox.poll(clock(210, 600));
    assert!(inbox.is_quarantined());
    assert_eq!(
        inbox.quarantine_until_nanos(),
        None,
        "do not schedule a past deadline"
    );
    let all_expired = correlation_for(1, 2, 210, 210, 200);
    no_show_or_history(&inbox.observe_service_clock(&all_expired, clock(210, 600)));
    assert!(!inbox.is_quarantined());
    assert_eq!(inbox.quarantine_until_nanos(), None);
    // This pure guard-budget fixture now explicitly consumes its pending
    // terminal delivery before expecting a new active reservation. Native
    // consumers must durably deduplicate journal insertion before durable ACK.
    assert_eq!(inbox.pending_outcomes().len(), 1);
    let pending = inbox.pending_outcomes()[0];
    assert_eq!(pending.key(), key(&first));
    assert_eq!(pending.outcome(), RequestOutcome::ExpiredLocally);
    assert_eq!(
        inbox.acknowledge_outcome(pending.delivery_id()),
        OutcomeAcknowledgment::Removed
    );
    assert!(inbox.pending_outcomes().is_empty());
    let new = opened(3, 210, 220);
    assert!(
        inbox
            .receive_opened(&new, &mut correlation, clock(210, 600))
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
}

#[test]
fn maximum_and_excess_identity_traffic_stays_bounded_without_live_eviction() {
    let limits = CapacityLimits::new(32, 512).expect("maximum supported limits");
    let mut inbox = PhoneInbox::new(NotificationPolicy::default(), limits);
    let mut correlation = correlation();
    for id in 1..=1_024 {
        let event = opened(id, 0, 100_000);
        let update = inbox.receive_opened(&event, &mut correlation, clock(1, 600));
        assert!(inbox.active_count() <= 32);
        assert!(inbox.retained_count() <= 512);
        assert!(update.effects().len() <= 2 * limits.max_retained() + 3);
        assert_eq!(inbox.fault(), None);
        if id > 512 {
            no_show_or_history(&update);
        }
    }
    assert_eq!(inbox.active_count(), 32);
    assert_eq!(inbox.retained_count(), 512);
    let first = opened(1, 0, 100_000);
    assert!(
        inbox
            .check_pending(key(&first), clock(2, 600))
            .request()
            .is_some()
    );
    let expired = inbox.poll(clock(100_000, 600));
    assert_eq!(
        expired
            .effects()
            .iter()
            .filter(|effect| matches!(effect, Effect::RecordOutcome { .. }))
            .count(),
        32
    );
    assert_eq!(inbox.retained_body_count(), 0);
    assert_eq!(inbox.retained_count(), 512, "source proof is still missing");
    let confirmed = correlation_for(1, 2, 100_000, 100_000, 100_000);
    no_show_or_history(&inbox.observe_service_clock(&confirmed, clock(100_000, 600)));
    assert_eq!(inbox.retained_count(), 0);
    assert_eq!(inbox.source_count(), 1, "watermark outlives retired guards");
    let old_untracked = opened(1_024, 0, 100_000);
    no_show_or_history(&inbox.receive_opened(
        &old_untracked,
        &mut correlation,
        clock(100_001, 600),
    ));
}

#[test]
fn native_submillisecond_regression_latches_and_withdraws_without_history() {
    let mut inbox = inbox();
    let mut correlation = correlation();
    let event = opened(1, 0, 10);
    inbox.receive_opened(&event, &mut correlation, clock_nanos(1_100_000, 600));
    let regressed = inbox.poll(clock_nanos(1_099_999, 600));
    assert_eq!(regressed.fault(), Some(InboxFault::NativeClockRegressed));
    assert!(regressed.effects().contains(&Effect::Withdraw {
        key: key(&event),
        reason: WithdrawalReason::EngineFault
    }));
    no_show_or_history(&regressed);
    assert_eq!(inbox.retained_body_count(), 0);
    assert!(
        inbox
            .check_pending(key(&event), clock(2, 600))
            .request()
            .is_none()
    );
    assert_eq!(
        inbox
            .receive_opened(&opened(2, 0, 10), &mut correlation, clock(3, 600))
            .fault(),
        Some(InboxFault::NativeClockRegressed)
    );
}

#[test]
fn externally_faulted_correlation_is_not_hidden_by_an_existing_cached_request() {
    let mut inbox = inbox();
    let mut correlation = correlation();
    let event = opened(1, 0, 10);
    inbox.receive_opened(&event, &mut correlation, clock(1, 600));
    correlation
        .map_request(&event, 2 * MILLI)
        .expect("external synthetic observation");
    assert!(correlation.map_request(&event, 2 * MILLI - 1).is_err());
    let result = inbox.receive_opened(&event, &mut correlation, clock(3, 600));
    assert_eq!(result.fault(), Some(InboxFault::ClockCorrelationFaulted));
    assert_eq!(inbox.retained_body_count(), 0);
    no_show_or_history(&result);
}

#[test]
fn upper_guard_overflow_is_a_latched_fail_closed_condition() {
    let mut inbox = inbox();
    let mut correlation = correlation_nanos(1, 2, u64::MAX - 10, u64::MAX - 5, 0);
    let content = Arc::new(
        RequestContent::new("합성", "C:\\Synthetic\\range.exe", "fixture").expect("content"),
    );
    let event = opened_parts(1, 2, 1, 0, 10, content);
    let result = inbox.receive_opened(&event, &mut correlation, clock_nanos(u64::MAX - 5, 600));
    assert_eq!(result.fault(), Some(InboxFault::ClockRangeExceeded));
    no_show_or_history(&result);
    assert_eq!(inbox.retained_body_count(), 0);
}

#[test]
fn pc_epoch_and_full_request_key_collisions_do_not_cross_resolve() {
    let mut inbox = inbox();
    let mut first_clock = correlation_for(1, 2, 0, 0, 0);
    let mut second_clock = correlation_for(2, 2, 0, 0, 0);
    let mut epoch_clock = correlation_for(1, 3, 0, 0, 0);
    let first = opened_for(1, 2, 1, 0, 1_000);
    let other_pc = opened_for(2, 2, 1, 0, 1_000);
    let other_epoch = opened_for(1, 3, 1, 0, 1_000);
    inbox.receive_opened(&first, &mut first_clock, clock(1, 600));
    inbox.receive_opened(&other_pc, &mut second_clock, clock(1, 600));
    inbox.receive_opened(&other_epoch, &mut epoch_clock, clock(1, 600));
    assert_eq!(inbox.active_count(), 3);
    assert_ne!(key(&first), key(&other_pc));
    assert_ne!(key(&first), key(&other_epoch));
    inbox.resolve_pc(
        &resolution(&other_pc, RequestResolution::Cancelled),
        &mut second_clock,
        clock(2, 600),
    );
    assert!(
        inbox
            .check_pending(key(&first), clock(3, 600))
            .request()
            .is_some()
    );
    assert!(
        inbox
            .check_pending(key(&other_epoch), clock(3, 600))
            .request()
            .is_some()
    );
    assert!(
        inbox
            .check_pending(key(&other_pc), clock(3, 600))
            .request()
            .is_none()
    );
}

#[test]
fn incoherent_clock_and_wrong_correlation_fail_without_polluting_inbox_state() {
    let reading = ClockReading::new(
        MonotonicTime::from_millis(1),
        LocalTime::new(Weekday::Monday, 600).expect("local"),
    );
    assert_eq!(
        InboxClock::new(reading, 2 * MILLI),
        Err(InboxIssue::IncoherentClock)
    );
    let mut inbox = inbox();
    let mut wrong_pc = correlation_for(2, 2, 0, 0, 0);
    let mut wrong_epoch = correlation_for(1, 3, 0, 0, 0);
    let event = opened(1, 0, 100);
    assert_eq!(
        inbox
            .receive_opened(&event, &mut wrong_pc, clock(1, 600))
            .issue(),
        Some(InboxIssue::WrongPc)
    );
    assert_eq!(
        inbox
            .receive_opened(&event, &mut wrong_epoch, clock(1, 600))
            .issue(),
        Some(InboxIssue::WrongEpoch)
    );
    assert_eq!(inbox.retained_count(), 0);
    assert_eq!(inbox.fault(), None);
}

#[test]
fn views_are_stale_snapshots_not_authority_and_debug_never_discloses_body() {
    let mut inbox = inbox();
    let mut correlation = correlation();
    let event = opened(1, 0, 100);
    let weak = body_weak(&event);
    let shown = inbox.receive_opened(&event, &mut correlation, clock(1, 600));
    let checked = inbox.check_pending(key(&event), clock(2, 600));
    let snapshot = checked.request().expect("checked body snapshot").clone();
    drop(checked);
    for diagnostic in [
        format!("{inbox:?}"),
        format!("{shown:?}"),
        format!("{snapshot:?}"),
    ] {
        assert!(!diagnostic.contains("inbox-fixture.exe"));
        assert!(!diagnostic.contains("synthetic inert"));
        assert!(!diagnostic.contains("합성 수신함"));
    }
    inbox.poll(clock(100, 600));
    assert_eq!(inbox.retained_body_count(), 0);
    assert!(
        inbox
            .check_pending(key(&event), clock(101, 600))
            .request()
            .is_none()
    );
    // Caller-owned snapshots cannot be revoked by Arc. They have no approval
    // methods/flags; native owner must discard them and recheck before acting.
    assert_eq!(snapshot.binding(), binding(&event));
    drop(event);
    assert_eq!(weak.strong_count(), 1);
    drop(snapshot);
    assert!(weak.upgrade().is_none());
}

#[test]
fn reconstruction_explicitly_does_not_claim_durable_replay_protection() {
    let event = opened(1, 0, 100_000);
    let mut before_restart = PhoneInbox::new(
        NotificationPolicy::new(Some(Schedule::Never), AlertMode::Sound),
        CapacityLimits::default(),
    );
    let mut old_clock = correlation();
    before_restart.receive_opened(&event, &mut old_clock, clock(1, 600));
    before_restart.update_policy(NotificationPolicy::default(), clock(2, 600));
    no_show_or_history(&before_restart.receive_opened(&event, &mut old_clock, clock(3, 600)));
    drop(before_restart);

    // Deliberate integration-gap test, NOT a production acceptance result:
    // new TLS/probe does not remember a prior process's discarded binding if a
    // PC reissues it. Native persistence/delivery cutoff must block this ingress.
    let mut after_restart = inbox();
    let mut new_clock = correlation_for(1, 2, 4, 4, 4);
    let incorrectly_reissued = after_restart.receive_opened(&event, &mut new_clock, clock(5, 600));
    assert!(
        incorrectly_reissued
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
}

#[test]
fn poll_at_schedule_end_withdraws_body_without_creating_an_outcome() {
    let mut inbox = PhoneInbox::new(
        weekly(600, 660, AlertMode::VibrateOnly),
        CapacityLimits::default(),
    );
    let mut correlation = correlation();
    let event = opened(1, 0, 120_000);
    inbox.receive_opened(&event, &mut correlation, clock(1, 659));
    let boundary = inbox.poll(clock(60_000, 660));
    assert_eq!(
        boundary.effects(),
        [Effect::Withdraw {
            key: key(&event),
            reason: WithdrawalReason::ScheduleBlocked
        }]
    );
    no_show_or_history(&boundary);
    assert_eq!(inbox.retained_body_count(), 0);
    no_show_or_history(&inbox.receive_opened(&event, &mut correlation, clock(60_001, 600)));
}

#[test]
fn unknown_resolution_at_capacity_is_covered_by_original_upper_quarantine() {
    let mut inbox = PhoneInbox::new(
        NotificationPolicy::default(),
        CapacityLimits::new(1, 1).expect("limits"),
    );
    let mut correlation = correlation_for(1, 2, 0, 10, 0);
    let first = opened(1, 0, 100);
    inbox.receive_opened(&first, &mut correlation, clock(11, 600));
    let untracked = opened(2, 0, 200);
    let result = inbox.resolve_pc(
        &resolution(&untracked, RequestResolution::Cancelled),
        &mut correlation,
        clock(12, 600),
    );
    assert_eq!(result.issue(), Some(InboxIssue::GuardCapacity));
    no_show_or_history(&result);
    assert_eq!(inbox.quarantine_until_nanos(), Some(210 * MILLI));
    inbox.poll(clock(110, 600));
    let first_expired = correlation_for(1, 2, 110, 110, 100);
    no_show_or_history(&inbox.observe_service_clock(&first_expired, clock(110, 600)));
    assert_eq!(inbox.retained_count(), 0);
    let late_open = inbox.receive_opened(&untracked, &mut correlation, clock(111, 600));
    assert_eq!(late_open.issue(), Some(InboxIssue::GuardQuarantine));
    no_show_or_history(&late_open);
}

#[test]
fn first_mapping_failure_is_body_free_and_not_retried_after_a_fresh_probe() {
    let mut inbox = inbox();
    let mut old_clock = correlation();
    let event = opened(1, 300_001, 301_000);
    let result = inbox.receive_opened(&event, &mut old_clock, clock(300_001, 600));
    assert_eq!(
        result.issue(),
        Some(InboxIssue::Clock(
            service_protocol::ClockError::CorrelationTooOld
        ))
    );
    no_show_or_history(&result);
    assert_eq!(inbox.retained_count(), 1);
    assert_eq!(inbox.retained_body_count(), 0);
    let mut new_clock = correlation_for(1, 2, 300_002, 300_002, 300_002);
    let retry = inbox.receive_opened(&event, &mut new_clock, clock(300_003, 600));
    assert!(has_drop(
        &retry,
        key(&event),
        DropReason::PreviouslySuppressed
    ));
    no_show_or_history(&retry);
}

#[test]
fn wrong_event_kind_cannot_create_a_request_or_resolution() {
    let mut inbox = inbox();
    let mut correlation = correlation();
    let event = opened(1, 0, 100);
    let closed = resolution(&event, RequestResolution::Cancelled);
    assert_eq!(
        inbox
            .receive_opened(&closed, &mut correlation, clock(1, 600))
            .issue(),
        Some(InboxIssue::WrongEventKind)
    );
    assert_eq!(
        inbox
            .resolve_pc(&event, &mut correlation, clock(1, 600))
            .issue(),
        Some(InboxIssue::WrongEventKind)
    );
    assert_eq!(inbox.retained_count(), 0);
    assert_eq!(inbox.active_count(), 0);
}

#[test]
fn off_hours_request_does_not_resurrect_when_service_clock_runs_fifty_ppm_slower() {
    let mut inbox = PhoneInbox::new(
        weekly(600, 660, AlertMode::Sound),
        CapacityLimits::default(),
    );
    let mut first = correlation_for(1, 2, 0, 1, 0);
    let event = opened(1, 0, 100_000);
    let discarded = inbox.receive_opened(&event, &mut first, clock(2, 599));
    assert!(has_drop(
        &discarded,
        key(&event),
        DropReason::OutsideAllowedTime
    ));
    no_show_or_history(&discarded);

    // The old phone-only upper bound is 100_001 ms. Both clocks remain
    // monotonic, but the service advances about 50 ppm more slowly: its new
    // authenticated sample is still below the original 100_000-ms expiry.
    // Passing the estimated phone upper bound must not forget the discard.
    no_show_or_history(&inbox.poll(clock(100_001, 600)));
    assert_eq!(
        inbox.next_deadline_nanos(),
        None,
        "wait for source evidence, not a past timer"
    );
    let mut later = correlation_for(1, 2, 100_001, 100_002, 99_996);
    let replay = inbox.receive_opened(&event, &mut later, clock(100_002, 600));
    // Remapping without a retained guard would produce a new lower expiry at
    // 100_005 ms and incorrectly Show the very same discarded signed request.
    no_show_or_history(&replay);
    assert_eq!(inbox.retained_body_count(), 0);
    assert!(
        inbox
            .check_pending(key(&event), clock(100_003, 600))
            .request()
            .is_none()
    );
}

#[test]
fn faster_service_clock_expires_active_body_once_without_faking_phone_time() {
    let mut inbox = inbox();
    let mut original = correlation_for(1, 2, 0, 1, 0);
    let event = opened(1, 0, 100_000);
    let weak = body_weak(&event);
    inbox.receive_opened(&event, &mut original, clock(2, 600));
    assert_eq!(weak.strong_count(), 2);

    let proof = correlation_for(1, 2, 99_995, 99_996, 100_000);
    let expired = inbox.observe_service_clock(&proof, clock(99_996, 600));
    assert_eq!(expired.fault(), None);
    assert_eq!(
        expired.effects(),
        [
            Effect::Withdraw {
                key: key(&event),
                reason: WithdrawalReason::ExpiredByPc
            },
            Effect::RecordOutcome {
                key: key(&event),
                outcome: RequestOutcome::ExpiredByPc
            },
        ]
    );
    assert_eq!(inbox.retained_body_count(), 0);
    assert_eq!(weak.strong_count(), 1);
    assert_eq!(
        inbox.retained_count(),
        1,
        "keep bookkeeping while local tombstone can remain"
    );
    assert_eq!(inbox.next_deadline_nanos(), Some(100_001 * MILLI));
    no_show_or_history(&inbox.observe_service_clock(&proof, clock(99_997, 600)));
    assert!(
        inbox
            .check_pending(key(&event), clock(99_997, 600))
            .request()
            .is_none()
    );
    no_show_or_history(&inbox.poll(clock(100_000, 600)));
    assert_eq!(inbox.retained_count(), 1);
    no_show_or_history(&inbox.poll(clock(100_001, 600)));
    assert_eq!(inbox.retained_count(), 0);
    assert_eq!(inbox.source_count(), 1);
    assert_eq!(inbox.fault(), None);
}

#[test]
fn retired_guard_watermark_rejects_old_correlation_replay_after_gc() {
    let mut inbox = PhoneInbox::new(
        weekly(600, 660, AlertMode::Sound),
        CapacityLimits::default(),
    );
    let mut original = correlation_for(1, 2, 0, 1, 0);
    let event = opened(1, 0, 100_000);
    inbox.receive_opened(&event, &mut original, clock(2, 599));
    let mut old_favorable = correlation_for(1, 2, 100_001, 100_002, 99_996);
    no_show_or_history(&inbox.receive_opened(&event, &mut old_favorable, clock(100_002, 600)));

    let proof = correlation_for(1, 2, 100_002, 100_002, 100_000);
    no_show_or_history(&inbox.observe_service_clock(&proof, clock(100_002, 600)));
    assert_eq!(inbox.retained_count(), 0);
    assert_eq!(inbox.source_count(), 1);
    // Alone this older mapping would still place expiry at phone 100_005 ms.
    let replay = inbox.receive_opened(&event, &mut old_favorable, clock(100_003, 600));
    assert!(has_drop(&replay, key(&event), DropReason::Expired));
    no_show_or_history(&replay);
    assert_eq!(
        inbox.retained_count(),
        0,
        "do not recreate an individually retired guard"
    );
    assert_eq!(inbox.retained_body_count(), 0);
    assert_eq!(inbox.fault(), None);
}

#[test]
fn first_expired_resolution_keeps_a_guard_even_after_its_phone_upper_estimate() {
    let mut inbox = inbox();
    let mut original = correlation_for(1, 2, 0, 1, 0);
    let event = opened(1, 0, 100_000);
    let expired = inbox.resolve_pc(
        &resolution(&event, RequestResolution::Expired),
        &mut original,
        clock(100_002, 600),
    );
    no_show_or_history(&expired);
    assert!(has_drop(&expired, key(&event), DropReason::Expired));
    assert_eq!(inbox.retained_count(), 1);
    assert_eq!(inbox.next_deadline_nanos(), None);
    let mut newer = correlation_for(1, 2, 100_001, 100_002, 99_996);
    no_show_or_history(&inbox.receive_opened(&event, &mut newer, clock(100_003, 600)));
    assert_eq!(inbox.retained_body_count(), 0);
}

#[test]
fn quarantine_survives_phone_upper_drift_until_source_and_phone_barriers_pass() {
    let mut inbox = PhoneInbox::new(
        weekly(600, 660, AlertMode::Sound),
        CapacityLimits::new(1, 1).expect("one guard/source slot"),
    );
    let mut original = correlation_for(1, 2, 0, 1, 0);
    let first = opened(1, 0, 100_000);
    let untracked = opened(2, 0, 100_000);
    inbox.receive_opened(&first, &mut original, clock(2, 599));
    assert_eq!(
        inbox
            .receive_opened(&untracked, &mut original, clock(3, 599))
            .issue(),
        Some(InboxIssue::GuardCapacity)
    );
    no_show_or_history(&inbox.poll(clock(100_001, 600)));
    assert!(inbox.is_quarantined());
    assert_eq!(inbox.quarantine_until_nanos(), None);
    assert_eq!(inbox.next_deadline_nanos(), None);

    let mut newer = correlation_for(1, 2, 100_001, 100_002, 99_996);
    let replay = inbox.receive_opened(&untracked, &mut newer, clock(100_002, 600));
    assert_eq!(replay.issue(), Some(InboxIssue::GuardQuarantine));
    no_show_or_history(&replay);
    assert_eq!(inbox.quarantine_until_nanos(), Some(100_006 * MILLI));
    let mut proof = correlation_for(1, 2, 100_003, 100_003, 100_000);
    no_show_or_history(&inbox.observe_service_clock(&proof, clock(100_003, 600)));
    assert_eq!(inbox.retained_count(), 0);
    assert!(
        inbox.is_quarantined(),
        "the remaining phone upper barrier still applies"
    );
    assert_eq!(inbox.next_deadline_nanos(), Some(100_006 * MILLI));
    no_show_or_history(&inbox.poll(clock(100_006, 600)));
    assert!(!inbox.is_quarantined());
    no_show_or_history(&inbox.receive_opened(&untracked, &mut newer, clock(100_006, 600)));
    let fresh = opened(3, 100_001, 100_010);
    assert!(
        inbox
            .receive_opened(&fresh, &mut proof, clock(100_006, 600))
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
    assert_eq!(inbox.fault(), None);
}

#[test]
fn global_quarantine_requires_expiry_proof_from_every_dropped_source() {
    let mut inbox = PhoneInbox::new(
        weekly(600, 660, AlertMode::Sound),
        CapacityLimits::new(1, 2).expect("two sources"),
    );
    let mut a = correlation_for(1, 2, 0, 1, 0);
    let mut b = correlation_for(2, 2, 0, 1, 0);
    inbox.receive_opened(&opened(1, 0, 100), &mut a, clock(2, 599));
    inbox.receive_opened(&opened(2, 0, 100), &mut a, clock(3, 599));
    assert_eq!(
        inbox
            .receive_opened(&opened(3, 0, 200), &mut a, clock(4, 599))
            .issue(),
        Some(InboxIssue::GuardCapacity)
    );
    assert_eq!(
        inbox
            .receive_opened(&opened_for(2, 2, 4, 0, 200), &mut b, clock(5, 599))
            .issue(),
        Some(InboxIssue::GuardQuarantine)
    );
    no_show_or_history(&inbox.poll(clock(201, 600)));

    let mut a_expired = correlation_for(1, 2, 201, 201, 200);
    no_show_or_history(&inbox.observe_service_clock(&a_expired, clock(201, 600)));
    assert_eq!(inbox.retained_count(), 0);
    assert_eq!(inbox.source_count(), 2);
    assert!(
        inbox.is_quarantined(),
        "source B has not proved its dropped expiry"
    );
    assert_eq!(inbox.next_deadline_nanos(), None);
    let b_expired = correlation_for(2, 2, 201, 201, 200);
    no_show_or_history(&inbox.observe_service_clock(&b_expired, clock(201, 600)));
    assert!(!inbox.is_quarantined());
    let fresh = opened(5, 200, 210);
    assert!(
        inbox
            .receive_opened(&fresh, &mut a_expired, clock(202, 600))
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
}

#[test]
fn source_slots_remain_bounded_after_guard_gc_and_exhaustion_is_latched() {
    let mut inbox = PhoneInbox::new(
        NotificationPolicy::default(),
        CapacityLimits::new(1, 1).expect("one source slot"),
    );
    let mut a = correlation();
    let event = opened(1, 0, 10);
    inbox.receive_opened(&event, &mut a, clock(1, 600));
    let expired = correlation_for(1, 2, 10, 10, 10);
    inbox.observe_service_clock(&expired, clock(10, 600));
    assert_eq!(inbox.retained_count(), 0);
    assert_eq!(inbox.source_count(), 1);
    let b = correlation_for(2, 2, 11, 11, 0);
    let full = inbox.observe_service_clock(&b, clock(11, 600));
    assert_eq!(full.fault(), Some(InboxFault::SourceCapacityReached));
    no_show_or_history(&full);
    assert_eq!(inbox.source_count(), 1);
    assert_eq!(
        inbox
            .observe_service_clock(&expired, clock(12, 600))
            .fault(),
        Some(InboxFault::SourceCapacityReached)
    );
}

#[test]
fn source_capacity_fault_releases_active_bodies_without_history() {
    let mut inbox = PhoneInbox::new(
        NotificationPolicy::default(),
        CapacityLimits::new(1, 1).expect("one source slot"),
    );
    let mut a = correlation();
    let event = opened(1, 0, 100);
    let weak = body_weak(&event);
    inbox.receive_opened(&event, &mut a, clock(1, 600));
    let b = correlation_for(2, 2, 2, 2, 0);
    let full = inbox.observe_service_clock(&b, clock(2, 600));
    assert_eq!(full.fault(), Some(InboxFault::SourceCapacityReached));
    assert!(full.effects().contains(&Effect::Withdraw {
        key: key(&event),
        reason: WithdrawalReason::EngineFault
    }));
    no_show_or_history(&full);
    assert_eq!(weak.strong_count(), 1);
    assert_eq!(inbox.retained_body_count(), 0);
}

#[test]
fn older_valid_source_samples_never_lower_the_persistent_watermark() {
    let mut inbox = inbox();
    let newest = correlation_for(1, 2, 0, 0, 1_000);
    no_show_or_history(&inbox.observe_service_clock(&newest, clock(1, 600)));
    let mut older = correlation_for(1, 2, 0, 0, 900);
    no_show_or_history(&inbox.observe_service_clock(&older, clock(2, 600)));
    let old_request = opened(1, 900, 950);
    let replay = inbox.receive_opened(&old_request, &mut older, clock(3, 600));
    assert!(has_drop(&replay, key(&old_request), DropReason::Expired));
    no_show_or_history(&replay);
    assert_eq!(inbox.retained_count(), 0);
    assert_eq!(inbox.source_count(), 1);
}

#[test]
fn explicit_clock_observation_rejects_faulted_correlation_without_a_fake_request() {
    let mut inbox = inbox();
    let mut current = correlation();
    let event = opened(1, 0, 100);
    inbox.receive_opened(&event, &mut current, clock(1, 600));
    current
        .map_request(&event, 2 * MILLI)
        .expect("synthetic native observation");
    assert!(current.map_request(&event, 2 * MILLI - 1).is_err());
    let faulted = inbox.observe_service_clock(&current, clock(3, 600));
    assert_eq!(faulted.fault(), Some(InboxFault::ClockCorrelationFaulted));
    assert!(faulted.effects().contains(&Effect::Withdraw {
        key: key(&event),
        reason: WithdrawalReason::EngineFault
    }));
    no_show_or_history(&faulted);
    assert_eq!(inbox.retained_body_count(), 0);
}

#[test]
fn source_watermark_never_expires_another_pc_or_service_epoch() {
    let mut inbox = inbox();
    let mut a = correlation_for(1, 2, 0, 0, 0);
    let mut b = correlation_for(2, 2, 0, 0, 0);
    let mut later_epoch = correlation_for(1, 3, 0, 0, 0);
    let first = opened_for(1, 2, 1, 0, 100);
    let other_pc = opened_for(2, 2, 1, 0, 100);
    let other_epoch = opened_for(1, 3, 1, 0, 100);
    inbox.receive_opened(&first, &mut a, clock(1, 600));
    inbox.receive_opened(&other_pc, &mut b, clock(1, 600));
    inbox.receive_opened(&other_epoch, &mut later_epoch, clock(1, 600));
    let proof = correlation_for(1, 2, 2, 2, 100);
    let retired = inbox.observe_service_clock(&proof, clock(2, 600));
    assert_eq!(retired.fault(), None);
    assert_eq!(
        retired
            .effects()
            .iter()
            .filter(|effect| matches!(effect, Effect::Withdraw { .. }))
            .count(),
        1
    );
    assert!(
        inbox
            .check_pending(key(&first), clock(3, 600))
            .request()
            .is_none()
    );
    assert!(
        inbox
            .check_pending(key(&other_pc), clock(3, 600))
            .request()
            .is_some()
    );
    assert!(
        inbox
            .check_pending(key(&other_epoch), clock(3, 600))
            .request()
            .is_some()
    );
    assert_eq!(inbox.retained_body_count(), 2);
    assert_eq!(inbox.source_count(), 3);
}

#[test]
fn explicit_clock_observation_cannot_precede_its_native_probe_completion() {
    let mut inbox = inbox();
    let mut original = correlation();
    let event = opened(1, 0, 100);
    inbox.receive_opened(&event, &mut original, clock(1, 600));
    let too_early = correlation_for(1, 2, 10, 11, 10);
    let faulted = inbox.observe_service_clock(&too_early, clock(10, 600));
    assert_eq!(faulted.fault(), Some(InboxFault::NativeClockRegressed));
    assert!(faulted.effects().contains(&Effect::Withdraw {
        key: key(&event),
        reason: WithdrawalReason::EngineFault
    }));
    no_show_or_history(&faulted);
    assert_eq!(inbox.retained_body_count(), 0);
}
