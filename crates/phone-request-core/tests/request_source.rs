// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic signed events and native-source metadata, not pairing/auth proof.

use std::sync::Arc;

use approval_protocol::{
    BootEpoch, ChallengeNonce, ExpiryTick, OsSession, PcIdentity, RequestBinding, RequestContent,
    RequestId,
};
use notification_policy::{DropReason, Schedule, Weekday};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use phone_request_core::{
    AlertMode, CapacityLimits, ClockReading, Effect, InboxClock, InboxIssue, InboxUpdate,
    InvalidReceivingGeneration, LocalTime, MonotonicTime, NotificationPolicy, PhoneBootId,
    PhoneInbox, ReceivingGeneration, request_key,
};
use service_protocol::{
    ClockCorrelation, ClockProbe, PcEvent, PcPublicKey, RequestResolution, ServiceTick,
    UnsignedPcEvent, VerifiedPcEvent,
};

const MILLI: u64 = 1_000_000;
fn pc() -> PcIdentity {
    PcIdentity::from_bytes([1; 32]).unwrap()
}
fn epoch() -> BootEpoch {
    BootEpoch::from_bytes([2; 32]).unwrap()
}
fn generation(value: u64) -> ReceivingGeneration {
    ReceivingGeneration::from_trusted_owner(value).unwrap()
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
fn verified(event: PcEvent) -> VerifiedPcEvent {
    let signer = SigningKey::from_slice(&[7; 32]).unwrap();
    let public =
        PcPublicKey::from_sec1_bytes(signer.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    let unsigned = UnsignedPcEvent::new(event).unwrap();
    let signature: Signature = signer.sign(&unsigned.signing_bytes());
    unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
        .verify(pc(), &public)
        .unwrap()
}
fn source(sent_ms: u64, sampled_ms: u64) -> ClockCorrelation {
    let probe = ClockProbe::start(pc(), sent_ms * MILLI).unwrap();
    let reply = verified(PcEvent::Clock {
        pc: pc(),
        epoch: epoch(),
        probe: probe.nonce(),
        sampled_at: ServiceTick::from_nanos_since_epoch(sampled_ms * MILLI),
    });
    probe.complete(&reply, sent_ms * MILLI).unwrap()
}
fn opened(id: u8, issued_ms: u64, expiry_ms: u64) -> VerifiedPcEvent {
    let content = Arc::new(
        RequestContent::new(
            "Synthetic source app",
            "C:\\Synthetic\\source.exe",
            "synthetic body",
        )
        .unwrap(),
    );
    let binding = RequestBinding::new(
        pc(),
        epoch(),
        OsSession::new(1, 3),
        RequestId::from_bytes([id; 32]).unwrap(),
        ChallengeNonce::from_bytes([5; 32]).unwrap(),
        content.digest(),
        ExpiryTick::from_nanos_since_epoch(expiry_ms * MILLI).unwrap(),
    );
    verified(PcEvent::Opened {
        binding,
        issued_at: ServiceTick::from_nanos_since_epoch(issued_ms * MILLI),
        content,
    })
}
fn binding(event: &VerifiedPcEvent) -> RequestBinding {
    match event.event() {
        PcEvent::Opened { binding, .. } | PcEvent::Resolved { binding, .. } => *binding,
        PcEvent::Clock { .. } => panic!("request fixture required"),
    }
}
fn resolved(event: &VerifiedPcEvent) -> VerifiedPcEvent {
    let PcEvent::Opened {
        binding, issued_at, ..
    } = event.event()
    else {
        panic!("opened fixture")
    };
    verified(PcEvent::Resolved {
        binding: *binding,
        issued_at: *issued_at,
        outcome: RequestResolution::Cancelled,
    })
}
fn receive(
    inbox: &mut PhoneInbox,
    event: &VerifiedPcEvent,
    generation: Option<ReceivingGeneration>,
    correlation: &mut ClockCorrelation,
    at: InboxClock,
) -> InboxUpdate {
    match generation {
        Some(generation) => inbox.receive_opened_from(event, generation, correlation, at),
        None => inbox.receive_opened(event, correlation, at),
    }
}
fn resolve(
    inbox: &mut PhoneInbox,
    event: &VerifiedPcEvent,
    generation: Option<ReceivingGeneration>,
    correlation: &mut ClockCorrelation,
    at: InboxClock,
) -> InboxUpdate {
    match generation {
        Some(generation) => inbox.resolve_pc_from(event, generation, correlation, at),
        None => inbox.resolve_pc(event, correlation, at),
    }
}
fn no_show_or_history(update: &InboxUpdate) {
    assert!(update.effects().iter().all(|effect| !matches!(
        effect,
        Effect::Show(_) | Effect::Restore(_) | Effect::RecordOutcome { .. }
    )));
}

#[test]
fn changed_receiving_generation_cannot_advance_clocks_or_rebind_the_original_request() {
    let mut inbox = PhoneInbox::new(NotificationPolicy::default(), CapacityLimits::default());
    let event = opened(1, 0, 1_000);
    let original = generation(1);
    let accepted = inbox.receive_opened_from(&event, original, &mut source(0, 0), clock(10));
    assert!(
        accepted
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
    assert_eq!(
        inbox.check_receiving_source(&event, Some(generation(2))),
        Err(InboxIssue::ConflictingReceivingSource)
    );
    // This otherwise-valid clock would expire the original request and advance
    // native time if the mismatched source were processed before rejection.
    let rejected =
        inbox.receive_opened_from(&event, generation(2), &mut source(500, 2_000), clock(500));
    assert_eq!(
        rejected.issue(),
        Some(InboxIssue::ConflictingReceivingSource)
    );
    assert!(rejected.effects().is_empty());
    assert!(rejected.fault().is_none());
    let checked = inbox.check_pending(request_key(binding(&event)), clock(20));
    let current = checked.request().unwrap();
    assert_eq!(current.receiving_generation(), Some(original));
    assert_eq!(
        current.original_window().phone_expiry_nanos(),
        1_000 * MILLI
    );
    assert!(checked.update().fault().is_none());
    let repeated = inbox.receive_opened_from(&event, original, &mut source(200, 100), clock(200));
    assert!(repeated.effects().iter().any(|effect| matches!(
        effect,
        Effect::Drop {
            reason: DropReason::DuplicateActive,
            ..
        }
    )));
    let checked = inbox.check_pending(request_key(binding(&event)), clock(201));
    assert_eq!(
        checked
            .request()
            .unwrap()
            .original_window()
            .phone_expiry_nanos(),
        1_000 * MILLI
    );
    assert_eq!(
        checked.request().unwrap().receiving_generation(),
        Some(original)
    );
}

#[test]
fn receiving_generation_is_nonzero_metadata_with_redacted_debug_only() {
    assert_eq!(
        ReceivingGeneration::from_trusted_owner(0),
        Err(InvalidReceivingGeneration)
    );
    assert_eq!(generation(1).get(), 1);
    assert_eq!(generation(u64::MAX).get(), u64::MAX);
    assert!(!format!("{:?}", generation(u64::MAX)).contains(&u64::MAX.to_string()));
}

#[test]
fn none_some_and_different_some_never_upgrade_downgrade_or_replace_original_source() {
    for (original, other) in [
        (None, Some(generation(1))),
        (Some(generation(1)), None),
        (Some(generation(1)), Some(generation(2))),
    ] {
        let mut inbox = PhoneInbox::new(NotificationPolicy::default(), CapacityLimits::default());
        let event = opened(1, 0, 1_000);
        let resolution = resolved(&event);
        let initial = receive(&mut inbox, &event, original, &mut source(0, 0), clock(10));
        assert!(
            initial
                .effects()
                .iter()
                .any(|effect| matches!(effect, Effect::Show(_)))
        );
        for incoming in [&event, &resolution] {
            assert_eq!(
                inbox.check_receiving_source(incoming, other),
                Err(InboxIssue::ConflictingReceivingSource)
            );
        }
        let rejected = receive(
            &mut inbox,
            &event,
            other,
            &mut source(500, 2_000),
            clock(500),
        );
        assert_eq!(
            rejected.issue(),
            Some(InboxIssue::ConflictingReceivingSource)
        );
        assert!(rejected.effects().is_empty());
        let rejected = resolve(
            &mut inbox,
            &resolution,
            other,
            &mut source(500, 2_000),
            clock(500),
        );
        assert_eq!(
            rejected.issue(),
            Some(InboxIssue::ConflictingReceivingSource)
        );
        assert!(rejected.effects().is_empty());
        assert!(inbox.pending_outcomes().is_empty());
        let checked = inbox.check_pending(request_key(binding(&event)), clock(20));
        assert_eq!(checked.request().unwrap().receiving_generation(), original);
        assert!(checked.update().fault().is_none());
        let completed = resolve(
            &mut inbox,
            &resolution,
            original,
            &mut source(0, 0),
            clock(21),
        );
        assert!(
            completed
                .effects()
                .iter()
                .any(|effect| matches!(effect, Effect::RecordOutcome { .. }))
        );
        assert_eq!(inbox.pending_outcomes().len(), 1);
        assert_eq!(inbox.active_count(), 0);
    }
}

#[test]
fn wrong_binding_and_issuance_take_precedence_without_advancing_time_or_source_watermarks() {
    let mut inbox = PhoneInbox::new(NotificationPolicy::default(), CapacityLimits::default());
    let event = opened(1, 0, 1_000);
    inbox.receive_opened_from(&event, generation(1), &mut source(0, 0), clock(10));
    let original = binding(&event);
    let PcEvent::Opened {
        content, issued_at, ..
    } = event.event()
    else {
        panic!("opened fixture")
    };
    let changed_binding = RequestBinding::new(
        original.pc(),
        original.epoch(),
        original.session(),
        original.request_id(),
        ChallengeNonce::from_bytes([6; 32]).unwrap(),
        original.content_digest(),
        original.expiry(),
    );
    let wrong_binding = verified(PcEvent::Opened {
        binding: changed_binding,
        issued_at: *issued_at,
        content: Arc::clone(content),
    });
    let wrong_issuance = opened(1, 1, 1_000);
    for (invalid, expected) in [
        (wrong_binding, InboxIssue::ConflictingBinding),
        (wrong_issuance, InboxIssue::ConflictingIssuedAt),
    ] {
        assert_eq!(
            inbox.check_receiving_source(&invalid, Some(generation(2))),
            Err(expected)
        );
        let rejected =
            inbox.receive_opened_from(&invalid, generation(2), &mut source(500, 2_000), clock(500));
        assert_eq!(rejected.issue(), Some(expected));
        assert!(rejected.effects().is_empty());
        let rejected_resolution = inbox.resolve_pc_from(
            &resolved(&invalid),
            generation(2),
            &mut source(500, 2_000),
            clock(500),
        );
        assert_eq!(rejected_resolution.issue(), Some(expected));
        assert!(rejected_resolution.effects().is_empty());
    }
    let checked = inbox.check_pending(request_key(original), clock(20));
    assert_eq!(
        checked.request().unwrap().receiving_generation(),
        Some(generation(1))
    );
    assert!(checked.update().fault().is_none());
}

#[test]
fn quiet_hours_guard_keeps_source_without_body_or_history_and_never_revives_on_retry() {
    let mut inbox = PhoneInbox::new(
        NotificationPolicy::new(Some(Schedule::Never), AlertMode::Sound),
        CapacityLimits::default(),
    );
    let event = opened(1, 0, 1_000);
    let weak = match event.event() {
        PcEvent::Opened { content, .. } => Arc::downgrade(content),
        _ => unreachable!(),
    };
    let dropped = inbox.receive_opened_from(&event, generation(1), &mut source(0, 0), clock(10));
    no_show_or_history(&dropped);
    assert_eq!(inbox.retained_count(), 1);
    assert_eq!(inbox.retained_body_count(), 0);
    assert_eq!(
        inbox.check_receiving_source(&event, Some(generation(1))),
        Ok(())
    );
    assert_eq!(
        inbox.check_receiving_source(&event, None),
        Err(InboxIssue::ConflictingReceivingSource)
    );
    no_show_or_history(&inbox.update_policy(NotificationPolicy::default(), clock(20)));
    let changed =
        inbox.receive_opened_from(&event, generation(2), &mut source(500, 2_000), clock(500));
    assert_eq!(
        changed.issue(),
        Some(InboxIssue::ConflictingReceivingSource)
    );
    assert!(changed.effects().is_empty());
    let repeated = inbox.receive_opened_from(&event, generation(1), &mut source(0, 0), clock(30));
    no_show_or_history(&repeated);
    assert!(repeated.effects().iter().any(|effect| matches!(
        effect,
        Effect::Drop {
            reason: DropReason::PreviouslySuppressed,
            ..
        }
    )));
    assert_eq!(inbox.retained_count(), 1);
    assert_eq!(inbox.retained_body_count(), 0);
    assert!(inbox.pending_outcomes().is_empty());
    assert!(
        inbox
            .check_pending(request_key(binding(&event)), clock(31))
            .request()
            .is_none()
    );
    drop(event);
    assert!(
        weak.upgrade().is_none(),
        "off-hours source guard must not own a body"
    );
}

#[test]
fn closure_before_open_captures_source_and_later_open_cannot_change_it_or_resurrect() {
    let mut inbox = PhoneInbox::new(NotificationPolicy::default(), CapacityLimits::default());
    let event = opened(1, 0, 1_000);
    let closed = inbox.resolve_pc_from(
        &resolved(&event),
        generation(1),
        &mut source(0, 0),
        clock(10),
    );
    no_show_or_history(&closed);
    assert_eq!(inbox.retained_count(), 1);
    assert_eq!(
        inbox.check_receiving_source(&event, Some(generation(2))),
        Err(InboxIssue::ConflictingReceivingSource)
    );
    let mismatched =
        inbox.receive_opened_from(&event, generation(2), &mut source(500, 2_000), clock(500));
    assert_eq!(
        mismatched.issue(),
        Some(InboxIssue::ConflictingReceivingSource)
    );
    let same = inbox.receive_opened_from(&event, generation(1), &mut source(0, 0), clock(20));
    no_show_or_history(&same);
    assert_eq!(inbox.active_count(), 0);
    assert!(inbox.pending_outcomes().is_empty());
}

#[test]
fn unmappable_first_guard_also_retains_source_and_cannot_gain_a_new_window() {
    let mut inbox = PhoneInbox::new(NotificationPolicy::default(), CapacityLimits::default());
    let event = opened(1, 0, 100);
    let expired = inbox.receive_opened_from(&event, generation(1), &mut source(0, 0), clock(200));
    no_show_or_history(&expired);
    assert_eq!(inbox.retained_count(), 1);
    let changed = inbox.receive_opened_from(&event, generation(2), &mut source(300, 0), clock(300));
    assert_eq!(
        changed.issue(),
        Some(InboxIssue::ConflictingReceivingSource)
    );
    assert!(changed.effects().is_empty());
    let same = inbox.receive_opened_from(&event, generation(1), &mut source(201, 0), clock(201));
    no_show_or_history(&same);
    assert_eq!(inbox.retained_count(), 1);
    assert_eq!(inbox.retained_body_count(), 0);
    assert!(inbox.fault().is_none());
}

#[test]
fn terminal_outcome_without_a_retired_guard_still_cannot_become_a_new_active_request() {
    let mut inbox = PhoneInbox::new(NotificationPolicy::default(), CapacityLimits::default());
    let event = opened(1, 0, 1_000);
    inbox.receive_opened_from(&event, generation(1), &mut source(0, 0), clock(10));
    let closed = inbox.resolve_pc_from(
        &resolved(&event),
        generation(1),
        &mut source(0, 0),
        clock(20),
    );
    assert!(
        closed
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::RecordOutcome { .. }))
    );
    assert_eq!(inbox.pending_outcomes().len(), 1);
    assert_eq!(
        inbox.check_receiving_source(&event, Some(generation(2))),
        Err(InboxIssue::ConflictingReceivingSource)
    );
    let retired = inbox.observe_service_clock(&source(1_001, 1_000), clock(1_001));
    no_show_or_history(&retired);
    assert_eq!(inbox.retained_count(), 0);
    // Outbox-only rows have no source field. No source is guessed or added;
    // the existing terminal/source-expiry barriers must still drop the packet.
    assert_eq!(
        inbox.check_receiving_source(&event, Some(generation(2))),
        Ok(())
    );
    let repeated =
        inbox.receive_opened_from(&event, generation(2), &mut source(1_002, 0), clock(1_002));
    no_show_or_history(&repeated);
    assert_eq!(inbox.active_count(), 0);
    assert_eq!(inbox.retained_count(), 0);
    assert_eq!(inbox.pending_outcomes().len(), 1);
}

#[test]
fn same_boot_body_recovery_requires_exact_original_option_and_keeps_its_generation() {
    for original in [None, Some(generation(1))] {
        let boot = PhoneBootId::from_native_boot_count(7).unwrap();
        let mut inbox = PhoneInbox::with_phone_boot(
            NotificationPolicy::default(),
            CapacityLimits::default(),
            boot,
        );
        let event = opened(1, 0, 1_000);
        receive(&mut inbox, &event, original, &mut source(0, 0), clock(10));
        let saved = inbox.checkpoint().unwrap();
        let (mut restored, initial) =
            PhoneInbox::restore_checkpoint(saved, boot, clock(20)).unwrap();
        no_show_or_history(&initial);
        assert_eq!(restored.recovering_count(), 1);
        assert_eq!(restored.retained_body_count(), 0);
        let different = if original.is_some() {
            None
        } else {
            Some(generation(1))
        };
        let rejected = receive(
            &mut restored,
            &event,
            different,
            &mut source(500, 2_000),
            clock(500),
        );
        assert_eq!(
            rejected.issue(),
            Some(InboxIssue::ConflictingReceivingSource)
        );
        assert!(rejected.effects().is_empty());
        assert_eq!(restored.recovering_count(), 1);
        let recovered = receive(
            &mut restored,
            &event,
            original,
            &mut source(30, 20),
            clock(30),
        );
        assert!(
            recovered
                .effects()
                .iter()
                .any(|effect| matches!(effect, Effect::Restore(_)))
        );
        assert!(
            !recovered
                .effects()
                .iter()
                .any(|effect| matches!(effect, Effect::Show(_)))
        );
        let checked = restored.check_pending(request_key(binding(&event)), clock(31));
        assert_eq!(checked.request().unwrap().receiving_generation(), original);
        assert_eq!(
            checked
                .request()
                .unwrap()
                .original_window()
                .phone_expiry_nanos(),
            1_000 * MILLI
        );
    }
}
