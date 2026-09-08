// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic signing fixtures and pure-core state tests, not device/OS evidence.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    sync::{Arc, Barrier, Mutex},
    thread,
    time::{Duration, Instant},
};

use approval_core::{
    ApprovalEngine, CancelError, ClockError, ConfigurationError, DecisionError, DeviceKeys,
    EngineError, EnrollmentError, MAX_PENDING_REQUESTS, MAX_REQUEST_TTL_MILLIS,
    MAX_TRUSTED_DEVICES, PendingChallenge, PrivilegedDeviceRegistry, RequestTtl,
};
use approval_protocol::{
    BootEpoch, ChallengeNonce, ContentDigest, DecisionPublicKey, DecisionPurpose, DeviceId,
    ExpiryTick, OsSession, PcIdentity, RequestBinding, RequestContent, RequestId, SignedDecision,
    UnsignedDecision,
};
use p256::{
    Scalar,
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::PrimeField,
};

struct PhoneFixture {
    device: DeviceId,
    approval: SigningKey,
    denial: SigningKey,
}

impl PhoneFixture {
    fn new(seed: u8) -> Self {
        Self {
            device: DeviceId::from_bytes([seed; 16]).unwrap(),
            approval: SigningKey::from_slice(&[seed * 2; 32]).unwrap(),
            denial: SigningKey::from_slice(&[seed * 2 + 1; 32]).unwrap(),
        }
    }

    fn public_keys(&self) -> DeviceKeys {
        let approval = DecisionPublicKey::from_sec1_bytes(
            self.approval
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap();
        let denial = DecisionPublicKey::from_sec1_bytes(
            self.denial
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap();
        DeviceKeys::new(approval, denial).unwrap()
    }

    fn sign(&self, binding: RequestBinding, purpose: DecisionPurpose) -> SignedDecision {
        sign_as(
            binding,
            self.device,
            purpose,
            match purpose {
                DecisionPurpose::Approve => &self.approval,
                DecisionPurpose::Deny => &self.denial,
            },
        )
    }
}

fn sign_as(
    binding: RequestBinding,
    device: DeviceId,
    purpose: DecisionPurpose,
    key: &SigningKey,
) -> SignedDecision {
    let statement = UnsignedDecision::new(binding, device, purpose);
    let signature: Signature = key.sign(&statement.signing_bytes());
    SignedDecision::from_der(statement, signature.to_der().as_bytes()).unwrap()
}

fn engine(
    phones: &[&PhoneFixture],
    device_capacity: usize,
    pending_capacity: usize,
    now: Instant,
) -> ApprovalEngine {
    let mut devices =
        PrivilegedDeviceRegistry::initialize_for_privileged_host(device_capacity).unwrap();
    for phone in phones {
        devices
            .enroll_from_privileged_host(phone.device, phone.public_keys())
            .unwrap();
    }
    ApprovalEngine::initialize_for_privileged_host(
        PcIdentity::from_bytes([42; 32]).unwrap(),
        devices,
        pending_capacity,
        now,
    )
    .unwrap()
}

fn open(engine: &mut ApprovalEngine, now: Instant, ttl_ms: u32) -> PendingChallenge {
    engine
        .open_from_privileged_host(
            OsSession::new(1, 0x1234),
            RequestContent::new(
                "Fixture App",
                r"C:\fixture\app.exe",
                "synthetic display data",
            )
            .unwrap(),
            RequestTtl::from_millis(ttl_ms).unwrap(),
            now,
        )
        .unwrap()
}

#[derive(Clone, Copy)]
struct BindingFields {
    pc: PcIdentity,
    epoch: BootEpoch,
    session: OsSession,
    request: RequestId,
    nonce: ChallengeNonce,
    content: ContentDigest,
    expiry: ExpiryTick,
}

impl From<RequestBinding> for BindingFields {
    fn from(binding: RequestBinding) -> Self {
        Self {
            pc: binding.pc(),
            epoch: binding.epoch(),
            session: binding.session(),
            request: binding.request_id(),
            nonce: binding.nonce(),
            content: binding.content_digest(),
            expiry: binding.expiry(),
        }
    }
}

impl BindingFields {
    fn binding(self) -> RequestBinding {
        RequestBinding::new(
            self.pc,
            self.epoch,
            self.session,
            self.request,
            self.nonce,
            self.content,
            self.expiry,
        )
    }
}

fn flip<const N: usize>(bytes: &[u8; N]) -> [u8; N] {
    let mut changed = *bytes;
    changed[0] ^= 0x80;
    changed
}

#[test]
fn approval_returns_only_an_exact_bound_one_shot_adapter_permission() {
    let phone = PhoneFixture::new(1);
    let now = Instant::now();
    let mut engine = engine(&[&phone], 2, 2, now);
    let challenge = open(&mut engine, now, 100);
    assert_eq!(challenge.binding().pc(), engine.pc_identity());
    assert_eq!(challenge.binding().epoch(), engine.boot_epoch());
    assert_eq!(challenge.binding().session(), OsSession::new(1, 0x1234));
    assert_eq!(
        challenge.binding().content_digest(),
        challenge.content().digest()
    );
    assert_eq!(challenge.eligible_devices(), &[phone.device]);
    let response = phone.sign(challenge.binding(), DecisionPurpose::Approve);
    let permission = engine
        .submit_decision(&response, now + Duration::from_millis(1))
        .unwrap();
    assert_eq!(permission.binding(), challenge.binding());
    assert_eq!(permission.content(), challenge.content());
    assert_eq!(permission.device_id(), phone.device);
    assert_eq!(permission.purpose(), DecisionPurpose::Approve);
    assert_eq!(permission.deadline(), now + Duration::from_millis(100));
    assert_eq!(engine.pending_count(), 0);
    assert_eq!(
        engine
            .submit_decision(&response, now + Duration::from_millis(2))
            .unwrap_err(),
        DecisionError::UnknownOrCompleted
    );
    assert!(!format!("{permission:?}").contains("synthetic display data"));
}

#[test]
fn every_binding_mutation_is_rejected_without_consuming_the_live_request() {
    let phone = PhoneFixture::new(1);
    let now = Instant::now();
    let mut engine = engine(&[&phone], 1, 1, now);
    let challenge = open(&mut engine, now, 100);
    let original = BindingFields::from(challenge.binding());
    let mut variants = Vec::new();
    let mut changed = original;
    changed.pc = PcIdentity::from_bytes(flip(original.pc.as_bytes())).unwrap();
    variants.push((changed.binding(), DecisionError::WrongPc));
    changed = original;
    changed.epoch = BootEpoch::from_bytes(flip(original.epoch.as_bytes())).unwrap();
    variants.push((changed.binding(), DecisionError::WrongEpoch));
    changed = original;
    changed.session = OsSession::new(2, original.session.logon_id());
    variants.push((changed.binding(), DecisionError::BindingMismatch));
    changed = original;
    changed.session = OsSession::new(original.session.session_id(), 0x5678);
    variants.push((changed.binding(), DecisionError::BindingMismatch));
    changed = original;
    changed.request = RequestId::from_bytes(flip(original.request.as_bytes())).unwrap();
    variants.push((changed.binding(), DecisionError::UnknownOrCompleted));
    changed = original;
    changed.nonce = ChallengeNonce::from_bytes(flip(original.nonce.as_bytes())).unwrap();
    variants.push((changed.binding(), DecisionError::BindingMismatch));
    changed = original;
    changed.content = ContentDigest::from_bytes(flip(original.content.as_bytes()));
    variants.push((changed.binding(), DecisionError::BindingMismatch));
    changed = original;
    changed.expiry =
        ExpiryTick::from_nanos_since_epoch(original.expiry.as_nanos_since_epoch() + 1).unwrap();
    variants.push((changed.binding(), DecisionError::BindingMismatch));
    for (binding, expected) in variants {
        let response = phone.sign(binding, DecisionPurpose::Approve);
        assert_eq!(
            engine.submit_decision(&response, now).unwrap_err(),
            expected
        );
        assert_eq!(engine.pending_count(), 1);
    }
    let permission = engine
        .submit_decision(
            &phone.sign(challenge.binding(), DecisionPurpose::Approve),
            now,
        )
        .unwrap();
    assert_eq!(permission.binding(), challenge.binding());
}

#[test]
fn presentation_clones_and_authorization_share_one_immutable_payload() {
    let phone = PhoneFixture::new(1);
    let now = Instant::now();
    let mut state = engine(&[&phone], 1, 1, now);
    let challenge = open(&mut state, now, 100);
    let presentation_copy = challenge.clone();
    assert!(std::ptr::eq(
        challenge.content(),
        presentation_copy.content()
    ));
    let permission = state
        .submit_decision(
            &phone.sign(challenge.binding(), DecisionPurpose::Approve),
            now,
        )
        .unwrap();
    assert!(std::ptr::eq(challenge.content(), permission.content()));
    for debug in [
        format!("{challenge:?}"),
        format!("{presentation_copy:?}"),
        format!("{permission:?}"),
    ] {
        assert!(!debug.contains("synthetic display data"));
        assert!(!debug.contains(r"C:\fixture\app.exe"));
    }
}

#[test]
fn failed_engine_enrollment_changes_preserve_live_snapshot_authority() {
    let first = PhoneFixture::new(1);
    let second = PhoneFixture::new(2);
    let absent = PhoneFixture::new(3);
    let now = Instant::now();
    let mut state = engine(&[&first, &second], 2, 1, now);
    let challenge = open(&mut state, now, 100);
    assert_eq!(state.enrolled_device_count(), 2);
    assert_eq!(
        state.replace_device_from_privileged_host(first.device, second.public_keys()),
        Err(EnrollmentError::KeyReuse)
    );
    assert_eq!(
        state.enroll_device_from_privileged_host(first.device, first.public_keys()),
        Err(EnrollmentError::AlreadyEnrolled)
    );
    assert_eq!(
        state.revoke_device_from_privileged_host(absent.device),
        Err(EnrollmentError::NotEnrolled)
    );
    assert_eq!(state.enrolled_device_count(), 2);
    let permission = state
        .submit_decision(
            &first.sign(challenge.binding(), DecisionPurpose::Approve),
            now,
        )
        .unwrap();
    assert_eq!(permission.device_id(), first.device);
}

#[test]
fn wrong_key_and_wrong_purpose_never_consume_then_valid_denial_wins() {
    let phone = PhoneFixture::new(1);
    let stranger = PhoneFixture::new(2);
    let now = Instant::now();
    let mut engine = engine(&[&phone], 1, 1, now);
    let challenge = open(&mut engine, now, 100);
    for (purpose, key) in [
        (DecisionPurpose::Approve, &phone.denial),
        (DecisionPurpose::Deny, &phone.approval),
        (DecisionPurpose::Approve, &stranger.approval),
    ] {
        let invalid = sign_as(challenge.binding(), phone.device, purpose, key);
        assert_eq!(
            engine.submit_decision(&invalid, now).unwrap_err(),
            DecisionError::InvalidSignature
        );
        assert_eq!(engine.pending_count(), 1);
    }
    // No Android authentication boolean or credential assertion can authorize
    // denial or approval: only the separately enrolled purpose key is checked.
    let denied = engine
        .submit_decision(&phone.sign(challenge.binding(), DecisionPurpose::Deny), now)
        .unwrap();
    assert_eq!(denied.purpose(), DecisionPurpose::Deny);
    assert_eq!(
        engine
            .submit_decision(
                &phone.sign(challenge.binding(), DecisionPurpose::Approve),
                now
            )
            .unwrap_err(),
        DecisionError::UnknownOrCompleted
    );
}

#[test]
fn unpaired_or_newly_enrolled_phones_are_not_in_a_pending_snapshot() {
    let first = PhoneFixture::new(1);
    let later = PhoneFixture::new(2);
    let now = Instant::now();
    let mut engine = engine(&[&first], 2, 2, now);
    let challenge = open(&mut engine, now, 100);
    let response = later.sign(challenge.binding(), DecisionPurpose::Approve);
    assert_eq!(
        engine.submit_decision(&response, now).unwrap_err(),
        DecisionError::NotEligible
    );
    engine
        .enroll_device_from_privileged_host(later.device, later.public_keys())
        .unwrap();
    assert_eq!(
        engine.submit_decision(&response, now).unwrap_err(),
        DecisionError::NotEligible
    );
    let newer = open(&mut engine, now, 100);
    let permission = engine
        .submit_decision(&later.sign(newer.binding(), DecisionPurpose::Deny), now)
        .unwrap();
    assert_eq!(permission.device_id(), later.device);
    let first_permission = engine
        .submit_decision(
            &first.sign(challenge.binding(), DecisionPurpose::Approve),
            now,
        )
        .unwrap();
    assert_eq!(first_permission.device_id(), first.device);
}

#[test]
fn copied_device_id_cannot_use_another_enrolled_phones_key() {
    let first = PhoneFixture::new(1);
    let second = PhoneFixture::new(2);
    let now = Instant::now();
    let mut engine = engine(&[&first, &second], 2, 1, now);
    let challenge = open(&mut engine, now, 100);
    let forged = sign_as(
        challenge.binding(),
        first.device,
        DecisionPurpose::Approve,
        &second.approval,
    );
    assert_eq!(
        engine.submit_decision(&forged, now).unwrap_err(),
        DecisionError::InvalidSignature
    );
    assert_eq!(engine.pending_count(), 1);
    let permission = engine
        .submit_decision(
            &second.sign(challenge.binding(), DecisionPurpose::Approve),
            now,
        )
        .unwrap();
    assert_eq!(permission.device_id(), second.device);
}

#[test]
fn revoke_and_reenroll_the_same_key_does_not_resurrect_pending_authority() {
    let first = PhoneFixture::new(1);
    let second = PhoneFixture::new(2);
    let now = Instant::now();
    let mut engine = engine(&[&first, &second], 2, 2, now);
    let challenge = open(&mut engine, now, 100);
    let old = first.sign(challenge.binding(), DecisionPurpose::Approve);
    engine
        .revoke_device_from_privileged_host(first.device)
        .unwrap();
    assert_eq!(
        engine.submit_decision(&old, now).unwrap_err(),
        DecisionError::EnrollmentChanged
    );
    engine
        .enroll_device_from_privileged_host(first.device, first.public_keys())
        .unwrap();
    assert_eq!(
        engine.submit_decision(&old, now).unwrap_err(),
        DecisionError::EnrollmentChanged
    );
    assert_eq!(engine.pending_count(), 1);
    let permission = engine
        .submit_decision(
            &second.sign(challenge.binding(), DecisionPurpose::Deny),
            now,
        )
        .unwrap();
    assert_eq!(permission.device_id(), second.device);
}

#[test]
fn replacement_keys_are_valid_only_for_new_requests() {
    let original = PhoneFixture::new(1);
    let replacement = PhoneFixture::new(2);
    let now = Instant::now();
    let mut engine = engine(&[&original], 1, 2, now);
    let old_challenge = open(&mut engine, now, 100);
    engine
        .replace_device_from_privileged_host(original.device, replacement.public_keys())
        .unwrap();
    for key in [&original.approval, &replacement.approval] {
        let response = sign_as(
            old_challenge.binding(),
            original.device,
            DecisionPurpose::Approve,
            key,
        );
        assert_eq!(
            engine.submit_decision(&response, now).unwrap_err(),
            DecisionError::EnrollmentChanged
        );
    }
    let new_challenge = open(&mut engine, now, 100);
    let response = sign_as(
        new_challenge.binding(),
        original.device,
        DecisionPurpose::Approve,
        &replacement.approval,
    );
    let permission = engine.submit_decision(&response, now).unwrap();
    assert_eq!(permission.binding(), new_challenge.binding());
    assert_eq!(engine.pending_count(), 1);
}

#[test]
fn even_identical_explicit_key_replacement_invalidates_the_old_snapshot() {
    let phone = PhoneFixture::new(1);
    let now = Instant::now();
    let mut engine = engine(&[&phone], 1, 1, now);
    let challenge = open(&mut engine, now, 100);
    engine
        .replace_device_from_privileged_host(phone.device, phone.public_keys())
        .unwrap();
    assert_eq!(
        engine
            .submit_decision(
                &phone.sign(challenge.binding(), DecisionPurpose::Approve),
                now
            )
            .unwrap_err(),
        DecisionError::EnrollmentChanged
    );
}

#[test]
fn registry_rejects_key_reuse_implicit_replacement_and_excess_capacity() {
    let first = PhoneFixture::new(1);
    let second = PhoneFixture::new(2);
    let third = PhoneFixture::new(3);
    let first_keys = first.public_keys();
    assert_eq!(
        DeviceKeys::new(first_keys.approval().clone(), first_keys.approval().clone()).unwrap_err(),
        EnrollmentError::KeyReuse
    );
    let mut registry = PrivilegedDeviceRegistry::initialize_for_privileged_host(2).unwrap();
    registry
        .enroll_from_privileged_host(first.device, first_keys.clone())
        .unwrap();
    assert_eq!(
        registry.enroll_from_privileged_host(first.device, second.public_keys()),
        Err(EnrollmentError::AlreadyEnrolled)
    );
    assert_eq!(
        registry.enroll_from_privileged_host(second.device, first_keys.clone()),
        Err(EnrollmentError::KeyReuse)
    );
    let cross_purpose = DeviceKeys::new(
        second.public_keys().approval().clone(),
        first_keys.approval().clone(),
    )
    .unwrap();
    assert_eq!(
        registry.enroll_from_privileged_host(second.device, cross_purpose),
        Err(EnrollmentError::KeyReuse)
    );
    registry
        .enroll_from_privileged_host(second.device, second.public_keys())
        .unwrap();
    assert_eq!(
        registry.replace_from_privileged_host(second.device, first_keys),
        Err(EnrollmentError::KeyReuse)
    );
    assert_eq!(
        registry.enroll_from_privileged_host(third.device, third.public_keys()),
        Err(EnrollmentError::CapacityReached)
    );
    assert_eq!(
        registry.replace_from_privileged_host(third.device, third.public_keys()),
        Err(EnrollmentError::NotEnrolled)
    );
    assert_eq!(
        registry.revoke_from_privileged_host(third.device),
        Err(EnrollmentError::NotEnrolled)
    );
    assert_eq!(registry.device_count(), 2);
    registry.revoke_from_privileged_host(first.device).unwrap();
    registry
        .enroll_from_privileged_host(third.device, third.public_keys())
        .unwrap();
    assert_eq!(registry.device_count(), 2);
}

#[test]
fn exact_deadline_and_later_are_rejected_but_one_nanosecond_before_is_live() {
    for elapsed in [
        Duration::from_millis(100) - Duration::from_nanos(1),
        Duration::from_millis(100),
        Duration::from_millis(101),
    ] {
        let phone = PhoneFixture::new(1);
        let now = Instant::now();
        let mut engine = engine(&[&phone], 1, 1, now);
        let challenge = open(&mut engine, now, 100);
        let result = engine.submit_decision(
            &phone.sign(challenge.binding(), DecisionPurpose::Approve),
            now + elapsed,
        );
        if elapsed < Duration::from_millis(100) {
            assert_eq!(result.unwrap().purpose(), DecisionPurpose::Approve);
        } else {
            assert_eq!(result.unwrap_err(), DecisionError::Expired);
        }
        assert_eq!(engine.pending_count(), 0);
    }
}

#[test]
fn expired_capacity_is_reclaimed_and_explicit_expiry_is_exact() {
    let phone = PhoneFixture::new(1);
    let now = Instant::now();
    let mut engine = engine(&[&phone], 1, 2, now);
    let first = open(&mut engine, now, 10);
    let second = open(&mut engine, now, 20);
    let capacity = engine.open_from_privileged_host(
        OsSession::new(1, 1),
        first.content().clone(),
        RequestTtl::from_millis(10).unwrap(),
        now,
    );
    assert_eq!(capacity.unwrap_err(), EngineError::PendingCapacityReached);
    assert!(
        engine
            .expire_from_privileged_host(now + Duration::from_millis(9))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        engine
            .expire_from_privileged_host(now + Duration::from_millis(10))
            .unwrap(),
        vec![first.binding().request_id()]
    );
    assert_eq!(engine.pending_count(), 1);
    assert_eq!(
        engine
            .submit_decision(
                &phone.sign(first.binding(), DecisionPurpose::Approve),
                now + Duration::from_millis(10)
            )
            .unwrap_err(),
        DecisionError::UnknownOrCompleted
    );
    let third = open(&mut engine, now + Duration::from_millis(20), 10);
    // Opening at second's exact deadline reclaims its capacity automatically.
    assert_eq!(engine.pending_count(), 1);
    assert_eq!(
        engine
            .submit_decision(
                &phone.sign(second.binding(), DecisionPurpose::Deny),
                now + Duration::from_millis(20)
            )
            .unwrap_err(),
        DecisionError::UnknownOrCompleted
    );
    assert_eq!(
        engine
            .expire_from_privileged_host(now + Duration::from_millis(30))
            .unwrap(),
        vec![third.binding().request_id()]
    );
}

#[test]
fn cancellation_checks_full_binding_and_response_cancel_races_have_one_winner() {
    let phone = PhoneFixture::new(1);
    let now = Instant::now();
    let mut engine = engine(&[&phone], 1, 1, now);
    let challenge = open(&mut engine, now, 100);
    let mut mismatch = BindingFields::from(challenge.binding());
    mismatch.content = ContentDigest::from_bytes([88; 32]);
    assert_eq!(
        engine.cancel_from_privileged_host(&mismatch.binding()),
        Err(CancelError::BindingMismatch)
    );
    assert_eq!(engine.pending_count(), 1);
    engine
        .cancel_from_privileged_host(&challenge.binding())
        .unwrap();
    assert_eq!(
        engine.cancel_from_privileged_host(&challenge.binding()),
        Err(CancelError::UnknownOrCompleted)
    );
    assert_eq!(
        engine
            .submit_decision(
                &phone.sign(challenge.binding(), DecisionPurpose::Approve),
                now
            )
            .unwrap_err(),
        DecisionError::UnknownOrCompleted
    );
    let next = open(&mut engine, now, 100);
    let permission = engine
        .submit_decision(&phone.sign(next.binding(), DecisionPurpose::Deny), now)
        .unwrap();
    assert_eq!(permission.purpose(), DecisionPurpose::Deny);
    assert_eq!(
        engine.cancel_from_privileged_host(&next.binding()),
        Err(CancelError::UnknownOrCompleted)
    );
}

#[test]
fn service_restart_discards_pending_and_rejects_the_old_epoch() {
    let phone = PhoneFixture::new(1);
    let now = Instant::now();
    let mut engine = engine(&[&phone], 1, 1, now);
    let before = open(&mut engine, now, 100);
    let old_response = phone.sign(before.binding(), DecisionPurpose::Approve);
    let next_time = now + Duration::from_millis(1);
    let epoch = engine.restart_from_privileged_host(next_time).unwrap();
    assert_ne!(epoch, before.binding().epoch());
    assert_eq!(engine.pending_count(), 0);
    assert_eq!(
        engine
            .submit_decision(&old_response, next_time)
            .unwrap_err(),
        DecisionError::WrongEpoch
    );
    let after = open(&mut engine, next_time, 100);
    assert_eq!(after.binding().expiry().as_nanos_since_epoch(), 100_000_000);
    assert_ne!(before.binding().request_id(), after.binding().request_id());
    assert_ne!(before.binding().nonce(), after.binding().nonce());
    let permission = engine
        .submit_decision(
            &phone.sign(after.binding(), DecisionPurpose::Approve),
            next_time,
        )
        .unwrap();
    assert_eq!(permission.binding().epoch(), epoch);
}

#[test]
fn clock_regression_fails_closed_without_consuming_a_live_request() {
    let phone = PhoneFixture::new(1);
    let now = Instant::now();
    let mut engine = engine(&[&phone], 1, 1, now);
    let challenge = open(&mut engine, now, 100);
    engine
        .expire_from_privileged_host(now + Duration::from_millis(10))
        .unwrap();
    let regressed = now + Duration::from_millis(9);
    let response = phone.sign(challenge.binding(), DecisionPurpose::Approve);
    assert_eq!(
        engine.submit_decision(&response, regressed).unwrap_err(),
        DecisionError::Clock(ClockError::WentBackwards)
    );
    assert_eq!(
        engine.expire_from_privileged_host(regressed),
        Err(ClockError::WentBackwards)
    );
    assert_eq!(
        engine.restart_from_privileged_host(regressed),
        Err(EngineError::Clock(ClockError::WentBackwards))
    );
    assert_eq!(
        engine
            .open_from_privileged_host(
                OsSession::new(1, 1),
                challenge.content().clone(),
                RequestTtl::from_millis(100).unwrap(),
                regressed
            )
            .unwrap_err(),
        EngineError::Clock(ClockError::WentBackwards)
    );
    assert_eq!(engine.pending_count(), 1);
    let permission = engine
        .submit_decision(&response, now + Duration::from_millis(11))
        .unwrap();
    assert_eq!(permission.binding(), challenge.binding());
}

#[test]
fn two_enrolled_phones_race_through_one_service_mutex_and_only_one_wins() {
    let first = PhoneFixture::new(1);
    let second = PhoneFixture::new(2);
    let now = Instant::now();
    let mut engine = engine(&[&first, &second], 2, 1, now);
    let challenge = open(&mut engine, now, 100);
    let responses = [
        first.sign(challenge.binding(), DecisionPurpose::Approve),
        second.sign(challenge.binding(), DecisionPurpose::Deny),
    ];
    let engine = Arc::new(Mutex::new(engine));
    let start = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for response in responses {
        let owner = Arc::clone(&engine);
        let barrier = Arc::clone(&start);
        handles.push(thread::spawn(move || {
            barrier.wait();
            owner.lock().unwrap().submit_decision(&response, now)
        }));
    }
    start.wait();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(DecisionError::UnknownOrCompleted)))
            .count(),
        1
    );
    assert_eq!(engine.lock().unwrap().pending_count(), 0);
}

#[test]
fn opposite_s_signature_representation_cannot_replay_a_consumed_request() {
    let phone = PhoneFixture::new(1);
    let now = Instant::now();
    let mut engine = engine(&[&phone], 1, 1, now);
    let challenge = open(&mut engine, now, 100);
    let statement =
        UnsignedDecision::new(challenge.binding(), phone.device, DecisionPurpose::Approve);
    let signature: Signature = phone.approval.sign(&statement.signing_bytes());
    let (r, s) = signature.split_bytes();
    let s_scalar = Option::<Scalar>::from(Scalar::from_repr(s)).unwrap();
    let other = Signature::from_scalars(r, (-s_scalar).to_bytes()).unwrap();
    let original = SignedDecision::from_der(statement, signature.to_der().as_bytes()).unwrap();
    let alternate = SignedDecision::from_der(statement, other.to_der().as_bytes()).unwrap();
    let permission = engine.submit_decision(&original, now).unwrap();
    assert_eq!(permission.purpose(), DecisionPurpose::Approve);
    assert_eq!(
        engine.submit_decision(&alternate, now).unwrap_err(),
        DecisionError::UnknownOrCompleted
    );
}

#[test]
fn empty_registry_and_invalid_configuration_fail_closed() {
    let now = Instant::now();
    for capacity in [0, MAX_TRUSTED_DEVICES + 1, usize::MAX] {
        assert_eq!(
            PrivilegedDeviceRegistry::initialize_for_privileged_host(capacity).unwrap_err(),
            ConfigurationError::InvalidDeviceCapacity
        );
    }
    assert!(PrivilegedDeviceRegistry::initialize_for_privileged_host(MAX_TRUSTED_DEVICES).is_ok());
    for capacity in [0, MAX_PENDING_REQUESTS + 1, usize::MAX] {
        let registry = PrivilegedDeviceRegistry::initialize_for_privileged_host(1).unwrap();
        assert_eq!(
            ApprovalEngine::initialize_for_privileged_host(
                PcIdentity::from_bytes([1; 32]).unwrap(),
                registry,
                capacity,
                now
            )
            .unwrap_err(),
            EngineError::Configuration(ConfigurationError::InvalidPendingCapacity)
        );
    }
    for ttl in [0, MAX_REQUEST_TTL_MILLIS + 1, u32::MAX] {
        assert_eq!(
            RequestTtl::from_millis(ttl),
            Err(ConfigurationError::InvalidRequestTtl)
        );
    }
    assert!(RequestTtl::from_millis(1).is_ok());
    assert!(RequestTtl::from_millis(MAX_REQUEST_TTL_MILLIS).is_ok());
    let mut engine = engine(&[], 1, 1, now);
    assert_eq!(
        engine
            .open_from_privileged_host(
                OsSession::new(1, 1),
                RequestContent::new("fixture", "path", "").unwrap(),
                RequestTtl::from_millis(100).unwrap(),
                now
            )
            .unwrap_err(),
        EngineError::NoEligibleDevices
    );
    assert_eq!(engine.pending_count(), 0);
}

#[test]
fn request_randomness_and_capacity_remain_bounded_under_many_opens() {
    let phone = PhoneFixture::new(1);
    let now = Instant::now();
    let mut engine = engine(&[&phone], 1, MAX_PENDING_REQUESTS, now);
    let mut ids = BTreeSet::new();
    let mut nonces = BTreeSet::new();
    for _ in 0..MAX_PENDING_REQUESTS {
        let challenge = open(&mut engine, now, 100);
        assert!(ids.insert(challenge.binding().request_id()));
        assert!(nonces.insert(*challenge.binding().nonce().as_bytes()));
    }
    assert_eq!(engine.pending_count(), MAX_PENDING_REQUESTS);
    assert_eq!(
        engine
            .open_from_privileged_host(
                OsSession::new(1, 1),
                RequestContent::new("fixture", "path", "").unwrap(),
                RequestTtl::from_millis(100).unwrap(),
                now
            )
            .unwrap_err(),
        EngineError::PendingCapacityReached
    );
    assert_eq!(
        engine
            .expire_from_privileged_host(now + Duration::from_millis(100))
            .unwrap()
            .len(),
        MAX_PENDING_REQUESTS
    );
    assert_eq!(engine.pending_count(), 0);
}
