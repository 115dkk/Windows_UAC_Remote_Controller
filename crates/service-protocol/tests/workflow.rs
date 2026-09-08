// SPDX-License-Identifier: GPL-2.0-or-later
//! Real library composition with synthetic keys/clocks, NOT Windows/phone QA.
use approval_core::{ApprovalEngine, DeviceKeys, PrivilegedDeviceRegistry, RequestTtl};
use approval_protocol::{
    DecisionPublicKey, DecisionPurpose, DeviceId, OsSession, PcIdentity, RequestContent,
    SignedDecision, UnsignedDecision,
};
use notification_policy::{
    AlertMode, AuthenticatedPcOutcome, AuthenticatedRequestMetadata, CapacityLimits, ClockReading,
    DayMask, Effect, LocalTime, MonotonicTime, NotificationEngine, NotificationPolicy, RequestKey,
    Schedule, TimeWindow, Weekday, WeeklySchedule,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use service_protocol::{
    ClockProbe, PcEvent, PcPublicKey, RequestResolution, ServiceTick, UnsignedPcEvent,
    VerifiedPcEvent,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

fn synthetic_key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}
fn verify_event(event: PcEvent) -> VerifiedPcEvent {
    let key = synthetic_key(11);
    let pc = event.pc();
    let unsigned = UnsignedPcEvent::new(event).unwrap();
    let signature: Signature = key.sign(&unsigned.signing_bytes());
    let wire = unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
        .to_wire();
    let public =
        PcPublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    VerifiedPcEvent::from_wire(&wire, pc, &public).unwrap()
}
fn phone_clock(ms: u64, minute: u16) -> ClockReading {
    ClockReading::new(
        MonotonicTime::from_millis(ms),
        LocalTime::new(Weekday::Monday, minute).unwrap(),
    )
}

#[test]
fn signed_request_to_phone_decision_preserves_service_binding_and_one_shot_authorization() {
    let start = Instant::now();
    let pc = PcIdentity::from_bytes([9; 32]).unwrap();
    let device = DeviceId::from_bytes([8; 16]).unwrap();
    let approval = synthetic_key(2);
    let denial = synthetic_key(3);
    let keys = DeviceKeys::new(
        DecisionPublicKey::from_sec1_bytes(
            approval.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap(),
        DecisionPublicKey::from_sec1_bytes(
            denial.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap(),
    )
    .unwrap();
    let mut registry = PrivilegedDeviceRegistry::initialize_for_privileged_host(1).unwrap();
    registry.enroll_from_privileged_host(device, keys).unwrap();
    let mut engine =
        ApprovalEngine::initialize_for_privileged_host(pc, registry, 2, start).unwrap();
    let challenge = engine
        .open_from_privileged_host(
            OsSession::new(1, 7),
            RequestContent::new("Example", "C:\\Synthetic\\example.exe", "synthetic only").unwrap(),
            RequestTtl::from_millis(60_000).unwrap(),
            start + Duration::from_secs(1),
        )
        .unwrap();
    let probe = ClockProbe::start(pc, 100_000_000_000).unwrap();
    let response = verify_event(PcEvent::Clock {
        pc,
        epoch: engine.boot_epoch(),
        probe: probe.nonce(),
        sampled_at: ServiceTick::from_nanos_since_epoch(2_000_000_000),
    });
    let mut clock = probe.complete(&response, 100_200_000_000).unwrap();
    let event = verify_event(PcEvent::Opened {
        binding: challenge.binding(),
        issued_at: ServiceTick::from_nanos_since_epoch(1_000_000_000),
        content: Arc::new(challenge.content().clone()),
    });
    let window = clock.map_request(&event, 100_200_000_000).unwrap();
    assert_eq!(window.phone_expiry_nanos(), 159_000_000_000);
    let binding = window.binding();
    let key = RequestKey::new(
        *binding.pc().as_bytes(),
        *binding.epoch().as_bytes(),
        *binding.request_id().as_bytes(),
    );
    let metadata = AuthenticatedRequestMetadata::new(
        key,
        MonotonicTime::from_millis(window.phone_issued_nanos() / 1_000_000),
        MonotonicTime::from_millis(window.phone_expiry_nanos() / 1_000_000),
    )
    .unwrap();
    let mut phone =
        NotificationEngine::new(NotificationPolicy::default(), CapacityLimits::default());
    assert!(
        phone
            .receive(metadata, phone_clock(100_200, 600))
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
    assert!(
        phone
            .check_pending(key, phone_clock(100_250, 600))
            .pending
            .is_some()
    );
    // Synthetic sign stands in for the future native per-use Keystore callback,
    // not for a proven biometric/credential operation or a UI authorization flag.
    let unsigned = UnsignedDecision::new(binding, device, DecisionPurpose::Approve);
    let signature: Signature = approval.sign(&unsigned.signing_bytes());
    let decision = SignedDecision::from_der(unsigned, signature.to_der().as_bytes()).unwrap();
    let parsed = SignedDecision::from_wire(&decision.to_wire()).unwrap();
    let authorized = engine
        .submit_decision(&parsed, start + Duration::from_secs(3))
        .unwrap();
    assert_eq!(authorized.binding(), challenge.binding());
    assert_eq!(authorized.content(), challenge.content());
    assert!(
        engine
            .submit_decision(&parsed, start + Duration::from_secs(3))
            .is_err()
    );
    // Drop instead of claiming an OS action. The Windows adapter is not exercised.
    drop(authorized);
    let resolved = verify_event(PcEvent::Resolved {
        binding,
        issued_at: window.service_issued_at(),
        outcome: RequestResolution::Failed,
    });
    assert!(matches!(
        resolved.event(),
        PcEvent::Resolved {
            outcome: RequestResolution::Failed,
            ..
        }
    ));
    let effects = phone.resolve_from_pc(
        metadata,
        AuthenticatedPcOutcome::Completed,
        phone_clock(101_000, 600),
    );
    assert!(
        effects
            .iter()
            .any(|effect| matches!(effect, Effect::Withdraw { .. }))
    );
    assert!(
        phone
            .check_pending(key, phone_clock(101_001, 600))
            .pending
            .is_none()
    );
}

#[test]
fn off_hours_request_stays_discarded_after_allowed_time_and_duplicate_delivery() {
    let content = Arc::new(
        RequestContent::new("Example", "C:\\Synthetic\\example.exe", "synthetic only").unwrap(),
    );
    let pc = PcIdentity::from_bytes([9; 32]).unwrap();
    let epoch = approval_protocol::BootEpoch::from_bytes([6; 32]).unwrap();
    let probe = ClockProbe::start(pc, 100_000_000_000).unwrap();
    let response = verify_event(PcEvent::Clock {
        pc,
        epoch,
        probe: probe.nonce(),
        sampled_at: ServiceTick::from_nanos_since_epoch(2_000_000_000),
    });
    let mut clock = probe.complete(&response, 100_100_000_000).unwrap();
    let binding = approval_protocol::RequestBinding::new(
        pc,
        epoch,
        OsSession::new(1, 7),
        approval_protocol::RequestId::from_bytes([4; 32]).unwrap(),
        approval_protocol::ChallengeNonce::from_bytes([5; 32]).unwrap(),
        content.digest(),
        approval_protocol::ExpiryTick::from_nanos_since_epoch(62_000_000_000).unwrap(),
    );
    let event = verify_event(PcEvent::Opened {
        binding,
        issued_at: ServiceTick::from_nanos_since_epoch(2_000_000_000),
        content,
    });
    let window = clock.map_request(&event, 100_100_000_000).unwrap();
    let metadata = AuthenticatedRequestMetadata::new(
        RequestKey::new(
            *pc.as_bytes(),
            *epoch.as_bytes(),
            *binding.request_id().as_bytes(),
        ),
        MonotonicTime::from_millis(window.phone_issued_nanos() / 1_000_000),
        MonotonicTime::from_millis(window.phone_expiry_nanos() / 1_000_000),
    )
    .unwrap();
    let schedule = Schedule::Weekly(
        WeeklySchedule::new([TimeWindow::new(
            DayMask::from_days(&[Weekday::Monday]).unwrap(),
            540,
            1080,
        )
        .unwrap()])
        .unwrap(),
    );
    let mut phone = NotificationEngine::new(
        NotificationPolicy::new(Some(schedule), AlertMode::Silent),
        CapacityLimits::default(),
    );
    for (time, minute) in [(100_100, 539), (101_000, 540)] {
        let effects = phone.receive(metadata, phone_clock(time, minute));
        assert!(
            !effects
                .iter()
                .any(|effect| matches!(effect, Effect::Show(_) | Effect::RecordOutcome { .. }))
        );
        assert!(
            phone
                .check_pending(metadata.key(), phone_clock(time, minute))
                .pending
                .is_none()
        );
    }
    assert_eq!(phone.active_count(), 0);
}
