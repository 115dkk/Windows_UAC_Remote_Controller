// SPDX-License-Identifier: GPL-2.0-or-later
//! Public core/codec contracts with synthetic signed events; no OS, peer
//! enrollment, native authentication, storage owner or validation is performed.
use approval_protocol::{
    BootEpoch, ChallengeNonce, ExpiryTick, OsSession, PcIdentity, RequestBinding, RequestContent,
    RequestId,
};
use notification_policy::{Schedule, Weekday};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use phone_request_core::{
    AlertMode, CapacityLimits, ClockReading, Effect, InboxCheckpoint, InboxCheckpointError,
    InboxClock, InboxIssue, LocalTime, MonotonicTime, NotificationPolicy, PhoneBootId, PhoneInbox,
    ReceivingGeneration, request_key,
};
use service_protocol::{
    ClockCorrelation, ClockProbe, PcEvent, PcPublicKey, RequestResolution, ServiceTick,
    UnsignedPcEvent, VerifiedPcEvent,
};
use std::sync::Arc;

const MILLI: u64 = 1_000_000;
const OUTCOME_BYTES: usize = 32 + 180 + 8 + 1;
const BODY: &str = "SYNTHETIC_SOURCE_BODY_NOT_CHECKPOINTED";
fn pc() -> PcIdentity {
    PcIdentity::from_bytes([1; 32]).unwrap()
}
fn epoch() -> BootEpoch {
    BootEpoch::from_bytes([2; 32]).unwrap()
}
fn boot(value: u32) -> PhoneBootId {
    PhoneBootId::from_native_boot_count(value).unwrap()
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
fn state(policy: NotificationPolicy) -> PhoneInbox {
    PhoneInbox::with_phone_boot(policy, CapacityLimits::default(), boot(7))
}
fn verified(event: PcEvent) -> VerifiedPcEvent {
    let signing = SigningKey::from_slice(&[7; 32]).unwrap();
    let public =
        PcPublicKey::from_sec1_bytes(signing.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    let unsigned = UnsignedPcEvent::new(event).unwrap();
    let signature: Signature = signing.sign(&unsigned.signing_bytes());
    unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
        .verify(pc(), &public)
        .unwrap()
}
fn source(phone_ms: u64, service_ms: u64) -> ClockCorrelation {
    let probe = ClockProbe::start(pc(), phone_ms * MILLI).unwrap();
    let event = verified(PcEvent::Clock {
        pc: pc(),
        epoch: epoch(),
        probe: probe.nonce(),
        sampled_at: ServiceTick::from_nanos_since_epoch(service_ms * MILLI),
    });
    probe.complete(&event, phone_ms * MILLI).unwrap()
}
fn opened(id: u64, expiry_ms: u64) -> VerifiedPcEvent {
    let mut request = [0u8; 32];
    request[..8].copy_from_slice(&id.to_be_bytes());
    let content = Arc::new(
        RequestContent::new("Synthetic source app", "C:\\Synthetic\\source.exe", BODY).unwrap(),
    );
    let binding = RequestBinding::new(
        pc(),
        epoch(),
        OsSession::new(3, 9),
        RequestId::from_bytes(request).unwrap(),
        ChallengeNonce::from_bytes([5; 32]).unwrap(),
        content.digest(),
        ExpiryTick::from_nanos_since_epoch(expiry_ms * MILLI).unwrap(),
    );
    verified(PcEvent::Opened {
        binding,
        issued_at: ServiceTick::from_nanos_since_epoch(0),
        content,
    })
}
fn binding(event: &VerifiedPcEvent) -> RequestBinding {
    let PcEvent::Opened { binding, .. } = event.event() else {
        panic!("synthetic opened event")
    };
    *binding
}
fn cancelled(event: &VerifiedPcEvent) -> VerifiedPcEvent {
    let PcEvent::Opened {
        binding, issued_at, ..
    } = event.event()
    else {
        panic!("synthetic opened event")
    };
    verified(PcEvent::Resolved {
        binding: *binding,
        issued_at: *issued_at,
        outcome: RequestResolution::Cancelled,
    })
}
fn saved(state: &PhoneInbox) -> InboxCheckpoint {
    InboxCheckpoint::from_bytes(&state.checkpoint().unwrap().to_bytes().unwrap()).unwrap()
}
fn no_positive(update: &phone_request_core::InboxUpdate) {
    assert!(
        update
            .effects()
            .iter()
            .all(|effect| !matches!(effect, Effect::Show(_) | Effect::Restore(_)))
    );
}
fn some_row_generation_offset(bytes: &[u8], outcome_count: usize) -> usize {
    // These fixtures have EXACTLY one retained Some row; the appended9-byte
    // field precedes the unchanged outcome count/tail. No production parser used.
    let offset = bytes.len() - (2 + outcome_count * OUTCOME_BYTES) - 9;
    assert_eq!(bytes[offset], 1);
    offset
}
fn one_row_as_v2(bytes: &[u8], outcome_count: usize) -> Vec<u8> {
    let offset = some_row_generation_offset(bytes, outcome_count);
    let mut old = bytes.to_vec();
    drop(old.drain(offset..offset + 9));
    old[8..10].copy_from_slice(&2u16.to_be_bytes());
    old
}

#[test]
fn original_generation_roundtrips_and_controls_same_boot_body_rehydration() {
    let mut original = state(NotificationPolicy::default());
    let event = opened(1, 10_000);
    let received = original.receive_opened_from(&event, generation(7), &mut source(0, 0), clock(0));
    assert!(
        received
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
    let bytes = original.checkpoint().unwrap().to_bytes().unwrap();
    assert_eq!(&bytes[8..10], &3u16.to_be_bytes());
    assert!(
        !bytes
            .windows(BODY.len())
            .any(|part| part == BODY.as_bytes())
    );
    let checkpoint = InboxCheckpoint::from_bytes(&bytes).unwrap();
    assert_eq!(
        checkpoint.receiving_sources().collect::<Vec<_>>(),
        vec![(pc(), generation(7))]
    );
    let (rebooted, reboot_update) =
        PhoneInbox::restore_checkpoint(checkpoint.clone(), boot(8), clock(0)).unwrap();
    no_positive(&reboot_update);
    assert_eq!(rebooted.retained_body_count(), 0);
    assert_eq!(rebooted.recovering_count(), 0);
    assert_eq!(
        saved(&rebooted).receiving_sources().collect::<Vec<_>>(),
        vec![(pc(), generation(7))]
    );
    let (mut restored, update) =
        PhoneInbox::restore_checkpoint(checkpoint, boot(7), clock(100)).unwrap();
    no_positive(&update);
    assert_eq!(restored.recovering_count(), 1);
    assert!(
        restored
            .check_pending(request_key(binding(&event)), clock(100))
            .request()
            .is_none()
    );
    let wrong =
        restored.receive_opened_from(&event, generation(8), &mut source(100, 100), clock(101));
    no_positive(&wrong);
    assert_eq!(wrong.issue(), Some(InboxIssue::ConflictingReceivingSource));
    assert_eq!(restored.retained_body_count(), 0);
    assert_eq!(
        saved(&restored).receiving_sources().collect::<Vec<_>>(),
        vec![(pc(), generation(7))]
    );
    let matching =
        restored.receive_opened_from(&event, generation(7), &mut source(100, 100), clock(102));
    assert!(
        matching
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Restore(_)))
    );
    let view = restored.check_pending(request_key(binding(&event)), clock(103));
    assert_eq!(
        view.request().unwrap().receiving_generation(),
        Some(generation(7))
    );
    assert_eq!(
        view.request()
            .unwrap()
            .original_window()
            .phone_expiry_nanos(),
        10_000 * MILLI
    );
}

#[test]
fn original_generation_survives_suppression_terminal_fault_and_another_phone_boot() {
    for terminal in [false, true] {
        let policy = if terminal {
            NotificationPolicy::default()
        } else {
            NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent)
        };
        let mut original = state(policy);
        let event = opened(2, 10_000);
        original.receive_opened_from(&event, generation(11), &mut source(0, 0), clock(0));
        if terminal {
            original.resolve_pc_from(
                &cancelled(&event),
                generation(11),
                &mut source(0, 0),
                clock(1),
            );
            assert_eq!(original.pending_outcomes().len(), 1);
        }
        assert_eq!(original.retained_body_count(), 0);
        let checkpoint = saved(&original);
        assert_eq!(
            checkpoint.receiving_sources().collect::<Vec<_>>(),
            vec![(pc(), generation(11))]
        );
        let (mut restored, update) =
            PhoneInbox::restore_checkpoint(checkpoint, boot(8), clock(1)).unwrap();
        no_positive(&update);
        assert_eq!(restored.retained_count(), 1);
        assert_eq!(restored.recovering_count(), 0);
        assert_eq!(
            saved(&restored).receiving_sources().collect::<Vec<_>>(),
            vec![(pc(), generation(11))]
        );
        restored.update_policy(NotificationPolicy::default(), clock(2));
        no_positive(&restored.receive_opened_from(
            &event,
            generation(11),
            &mut source(1, 0),
            clock(3),
        ));
        assert_eq!(restored.retained_body_count(), 0);
    }
    let mut faulted = state(NotificationPolicy::default());
    faulted.receive_opened_from(
        &opened(3, 10_000),
        generation(12),
        &mut source(0, 0),
        clock(0),
    );
    let _ = faulted.stop_for_owner_failure();
    let (restored, update) =
        PhoneInbox::restore_checkpoint(saved(&faulted), boot(8), clock(1)).unwrap();
    no_positive(&update);
    assert_eq!(
        saved(&restored).receiving_sources().collect::<Vec<_>>(),
        vec![(pc(), generation(12))]
    );
}

#[test]
fn explicitly_decoded_v2_has_no_source_and_cannot_upgrade_to_a_new_some_generation() {
    let mut original = state(NotificationPolicy::default());
    let event = opened(4, 10_000);
    original.receive_opened_from(&event, generation(17), &mut source(0, 0), clock(0));
    let current = original.checkpoint().unwrap().to_bytes().unwrap();
    let v2 = one_row_as_v2(&current, 0);
    let checkpoint = InboxCheckpoint::from_bytes(&v2).unwrap();
    assert_eq!(checkpoint.receiving_sources().count(), 0);
    let rewritten = checkpoint.to_bytes().unwrap();
    assert_eq!(rewritten.len(), v2.len() + 1); // Canonical schema3 None tag, not Some.
    let (rebooted, reboot_update) =
        PhoneInbox::restore_checkpoint(checkpoint.clone(), boot(8), clock(0)).unwrap();
    no_positive(&reboot_update);
    assert_eq!(saved(&rebooted).receiving_sources().count(), 0);
    assert_eq!(
        rebooted.check_receiving_source(&event, Some(generation(17))),
        Err(InboxIssue::ConflictingReceivingSource)
    );
    let (mut restored, _) =
        PhoneInbox::restore_checkpoint(checkpoint, boot(7), clock(100)).unwrap();
    assert_eq!(restored.retained_count(), 1);
    assert!(restored.check_receiving_source(&event, None).is_ok());
    assert!(
        restored
            .check_receiving_source(&event, Some(generation(17)))
            .is_err()
    );
    let attempt =
        restored.receive_opened_from(&event, generation(17), &mut source(100, 100), clock(101));
    no_positive(&attempt);
    assert_eq!(
        attempt.issue(),
        Some(InboxIssue::ConflictingReceivingSource)
    );
    assert_eq!(restored.retained_body_count(), 0);
    assert_eq!(saved(&restored).receiving_sources().count(), 0);
}

#[test]
fn v2_outcome_tail_remains_readable_without_inventing_a_guard_source() {
    let mut original = state(NotificationPolicy::default());
    let event = opened(5, 10_000);
    original.receive_opened_from(&event, generation(21), &mut source(0, 0), clock(0));
    original.resolve_pc_from(
        &cancelled(&event),
        generation(21),
        &mut source(0, 0),
        clock(1),
    );
    assert_eq!(original.pending_outcomes().len(), 1);
    let current = original.checkpoint().unwrap().to_bytes().unwrap();
    let old = one_row_as_v2(&current, 1);
    let checkpoint = InboxCheckpoint::from_bytes(&old).unwrap();
    assert_eq!(checkpoint.pending_outcomes(), original.pending_outcomes());
    assert_eq!(checkpoint.receiving_sources().count(), 0);
    let reread = InboxCheckpoint::from_bytes(&checkpoint.to_bytes().unwrap()).unwrap();
    assert_eq!(reread.pending_outcomes(), checkpoint.pending_outcomes());
    assert_eq!(reread.receiving_sources().count(), 0);
}

#[test]
fn current_generation_tags_zero_values_truncation_and_unknown_versions_are_strict() {
    let mut original = state(NotificationPolicy::default());
    original.receive_opened_from(
        &opened(6, 10_000),
        generation(1),
        &mut source(0, 0),
        clock(0),
    );
    let bytes = original.checkpoint().unwrap().to_bytes().unwrap();
    let offset = some_row_generation_offset(&bytes, 0);
    for invalid_tag in [2, 3, 127, 255] {
        let mut changed = bytes.clone();
        changed[offset] = invalid_tag;
        assert_eq!(
            InboxCheckpoint::from_bytes(&changed).unwrap_err(),
            InboxCheckpointError::InvalidState
        );
    }
    let mut zero = bytes.clone();
    zero[offset + 1..offset + 9].fill(0);
    assert_eq!(
        InboxCheckpoint::from_bytes(&zero).unwrap_err(),
        InboxCheckpointError::InvalidState
    );
    // Shape validation does not query current association liveness/highwater.
    // The trusted composite owner checks this nonzero scalar separately.
    let mut high = bytes.clone();
    high[offset + 1..offset + 9].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        InboxCheckpoint::from_bytes(&high)
            .unwrap()
            .receiving_sources()
            .collect::<Vec<_>>(),
        vec![(pc(), generation(u64::MAX))]
    );
    for end in 0..bytes.len() {
        assert!(InboxCheckpoint::from_bytes(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        InboxCheckpoint::from_bytes(&trailing).unwrap_err(),
        InboxCheckpointError::InvalidState
    );
    let mut missing = bytes.clone();
    drop(missing.drain(offset..offset + 9));
    assert!(InboxCheckpoint::from_bytes(&missing).is_err()); // No schema2 fallback.
    let mut unknown = bytes;
    unknown[8..10].copy_from_slice(&9u16.to_be_bytes());
    assert_eq!(
        InboxCheckpoint::from_bytes(&unknown).unwrap_err(),
        InboxCheckpointError::UnsupportedVersion
    );
}

#[test]
fn all_retained_source_fields_cost_exactly_4608_bytes_over_the_same_v2_state() {
    const RETAINED: usize = 512;
    // This fixture has mapped, inactive/suppressed guards: the published old row
    // is binding180+issued8+window17+metadata1+guard8+active1+recovery1+engine1=217.
    const V2_SUPPRESSED_ROW: usize = 217;
    let limits = CapacityLimits::new(32, RETAINED).unwrap();
    assert!(CapacityLimits::new(32, RETAINED + 1).is_err());
    let policy = NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent);
    let mut inbox = PhoneInbox::with_phone_boot(policy, limits, boot(7));
    let mut correlation = source(0, 0);
    for id in 1..=RETAINED {
        no_positive(&inbox.receive_opened_from(
            &opened(id as u64, 60_000),
            generation(31),
            &mut correlation,
            clock(0),
        ));
    }
    assert_eq!(inbox.retained_count(), RETAINED);
    assert_eq!(inbox.retained_body_count(), 0);
    assert!(inbox.pending_outcomes().is_empty());
    let bytes = inbox.checkpoint().unwrap().to_bytes().unwrap();
    let row_bytes = V2_SUPPRESSED_ROW + 9;
    let start = bytes.len() - 2 - RETAINED * row_bytes;
    let mut old = bytes[..start].to_vec();
    for row in bytes[start..bytes.len() - 2].chunks_exact(row_bytes) {
        assert_eq!(row[V2_SUPPRESSED_ROW], 1);
        assert_eq!(&row[V2_SUPPRESSED_ROW + 1..], &31u64.to_be_bytes());
        old.extend_from_slice(&row[..V2_SUPPRESSED_ROW]);
    }
    old.extend_from_slice(&[0, 0]); // The unchanged, empty schema2 outcome tail.
    old[8..10].copy_from_slice(&2u16.to_be_bytes());
    let legacy = InboxCheckpoint::from_bytes(&old).unwrap();
    assert_eq!(legacy.receiving_sources().count(), 0);
    assert_eq!(bytes.len() - old.len(), 9 * RETAINED);
    assert_eq!(9 * RETAINED, 4_608);
    let checkpoint = InboxCheckpoint::from_bytes(&bytes).unwrap();
    assert_eq!(checkpoint.receiving_sources().count(), RETAINED);
    assert!(
        checkpoint
            .receiving_sources()
            .all(|(owner, value)| owner == pc() && value == generation(31))
    );
    assert!(bytes.len() <= 384 * 1024);
    let (restored, _) = PhoneInbox::restore_checkpoint(checkpoint, boot(8), clock(0)).unwrap();
    assert_eq!(restored.retained_count(), RETAINED);
    assert_eq!(saved(&restored).receiving_sources().count(), RETAINED);
}
