// SPDX-License-Identifier: GPL-2.0-or-later
//! Real host store/controller composition plus synthetic public key evidence.
//! Callback counters/opaque certificate bytes are NOT Android/attestation QA.

use android_controller::{ControllerCheckpoint, LocalKeySetPhase};
use notification_policy::{CapacityLimits, NotificationPolicy};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use phone_state_store::{
    NativePrivateDirectory, SNAPSHOT_FILE_NAME, STAGING_FILE_NAME, SnapshotStore,
};
use service_protocol::{
    EnrollmentAcceptanceFields, FrozenCandidateFields, MAX_FROZEN_CANDIDATE_BYTES,
    UnsignedEnrollmentAcceptance, UnsignedFrozenCandidate,
};
use std::{
    fs,
    sync::atomic::{AtomicU64, AtomicUsize},
    time::Duration,
};

use super::*;
use crate::*;

struct TestClock {
    origin: Instant,
    seconds: AtomicU64,
    fail: AtomicBool,
    reads: AtomicU64,
    stop_on_read: AtomicU64,
    fail_on_read: AtomicU64,
    seconds_on_read: Mutex<Option<(u64, u64)>>,
    controller: Mutex<Weak<MobileController>>,
}
impl SocketClock for TestClock {
    fn now(&self) -> Result<Instant, framed_transport::SocketClockUnavailable> {
        let read = self.reads.fetch_add(1, Ordering::AcqRel) + 1;
        if self.stop_on_read.load(Ordering::Acquire) == read
            && let Some(controller) = self.controller.lock().unwrap().upgrade()
        {
            controller.stop_intake();
        }
        if let Some((at, seconds)) = *self.seconds_on_read.lock().unwrap()
            && at == read
        {
            self.seconds.store(seconds, Ordering::Release);
        }
        if self.fail_on_read.load(Ordering::Acquire) == read {
            self.fail.store(true, Ordering::Release);
        }
        if self.fail.load(Ordering::Acquire) {
            return Err(framed_transport::SocketClockUnavailable);
        }
        Ok(self.origin + Duration::from_secs(self.seconds.load(Ordering::Acquire)))
    }
}

#[derive(Clone, Copy, Default)]
enum Mode {
    #[default]
    Happy,
    ErrorBeforeTake,
    ErrorAfterTake,
    NoTake,
    ExpireBeforeTake,
    ExpireAfterReply,
    RegressBeforeTake,
    StopAfterReply,
    ClockFailsBeforeTake,
    ClockFailsAfterReply,
    WrongHandle,
    WrongChallenge,
    WrongNonce,
    DuplicateKey,
    PcKeyAsPhoneKey,
    InvalidSpki,
    EmptyChain,
    TooManyCertificates,
    LargeCertificate,
    LargeChain,
    BlockFinalCommit,
    PanicAfterTake,
}

struct Platform {
    path: String,
    clock: Arc<TestClock>,
    mode: Mutex<Mode>,
    controller: Mutex<Weak<MobileController>>,
    calls: AtomicUsize,
    created: AtomicUsize,
    cleanup: AtomicUsize,
    cleanup_fails: AtomicBool,
    saw_preparing: AtomicBool,
    saw_busy: AtomicBool,
    request: Mutex<Option<Arc<NativeKeyCreationRequest>>>,
}

fn public(seed: u8) -> TlsPublicKey {
    let signing = SigningKey::from_slice(&[seed; 32]).unwrap();
    let key = p256::PublicKey::from_sec1_bytes(
        signing.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .unwrap();
    TlsPublicKey::from_spki_der(key.to_public_key_der().unwrap().as_bytes()).unwrap()
}
fn evidence(input: NativeKeyCreationInput) -> NativeCreatedKeyEvidence {
    let role = |seed| NativeCreatedRoleEvidence {
        spki: public(seed).as_spki_der().to_vec(),
        // Explicitly opaque synthetic public evidence, not signed X.509.
        certificates: vec![vec![seed; 16]],
    };
    NativeCreatedKeyEvidence {
        handle: input.handle,
        challenge: input.challenge,
        ceremony_nonce: input.ceremony_nonce,
        approval: role(3),
        denial: role(4),
        transport: role(5),
    }
}
fn snapshot(path: &str) -> ControllerCheckpoint {
    let framed = fs::read(std::path::Path::new(path).join(SNAPSHOT_FILE_NAME)).unwrap();
    // Existing SnapshotStore v1 frame is prefix22 + SHA25632 bytes. This is a
    // read-only fixture assertion over REAL committed bytes, not another store.
    ControllerCheckpoint::from_bytes(&framed[54..]).unwrap()
}

impl NativePlatform for Platform {
    fn create_local_key_set(
        &self,
        request: Arc<NativeKeyCreationRequest>,
    ) -> Result<NativeCreatedKeyEvidence, BridgeError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let checkpoint = snapshot(&self.path);
        assert!(matches!(
            checkpoint
                .local_keys()
                .get(LocalKeyHandle::from_bytes([1; 32]).unwrap()),
            Some(LocalKeySetPhase::Preparing { .. })
        ));
        assert!(
            SnapshotStore::open_existing(
                NativePrivateDirectory::from_native_app_data(&self.path).unwrap()
            )
            .is_err()
        );
        self.saw_preparing.store(true, Ordering::Release);
        let controller = self.controller.lock().unwrap().upgrade().unwrap();
        assert!(controller.state.try_lock().unwrap().is_none());
        self.saw_busy.store(
            controller.notification_policy_json() == Err(BridgeError::Busy),
            Ordering::Release,
        );
        *self.request.lock().unwrap() = Some(Arc::clone(&request));
        let mode = *self.mode.lock().unwrap();
        match mode {
            Mode::ErrorBeforeTake => return Err(BridgeError::NativeUnavailable),
            Mode::ExpireBeforeTake => self.clock.seconds.store(301, Ordering::Release),
            Mode::RegressBeforeTake => self.clock.seconds.store(0, Ordering::Release),
            Mode::ClockFailsBeforeTake => self.clock.fail.store(true, Ordering::Release),
            Mode::NoTake => {
                return Ok(evidence(NativeKeyCreationInput {
                    handle: vec![1; 32],
                    challenge: vec![65; 32],
                    ceremony_nonce: vec![2; 32],
                }));
            }
            _ => (),
        }
        let input = request.take_input()?;
        assert!(request.take_input().is_err());
        request.check_current()?;
        self.created.fetch_add(1, Ordering::AcqRel);
        if matches!(mode, Mode::ErrorAfterTake) {
            return Err(BridgeError::NativeUnavailable);
        }
        assert!(
            !matches!(mode, Mode::PanicAfterTake),
            "synthetic callback unwind"
        );
        let mut value = evidence(input);
        match mode {
            Mode::ExpireAfterReply => self.clock.seconds.store(301, Ordering::Release),
            Mode::StopAfterReply => controller.stop_intake(),
            Mode::ClockFailsAfterReply => self.clock.fail.store(true, Ordering::Release),
            Mode::WrongHandle => value.handle = vec![99; 32],
            Mode::WrongChallenge => value.challenge = vec![99; 32],
            Mode::WrongNonce => value.ceremony_nonce = vec![99; 32],
            Mode::DuplicateKey => value.denial.spki = value.approval.spki.clone(),
            Mode::PcKeyAsPhoneKey => value.approval.spki = public(20).as_spki_der().to_vec(),
            Mode::InvalidSpki => value.transport.spki.push(0),
            Mode::EmptyChain => value.approval.certificates.clear(),
            Mode::TooManyCertificates => value.denial.certificates = vec![vec![1]; 9],
            Mode::LargeCertificate => {
                value.transport.certificates = vec![vec![1; MAX_CREATION_CERTIFICATE_BYTES + 1]]
            }
            Mode::LargeChain => {
                value.transport.certificates = vec![vec![1; MAX_CREATION_CERTIFICATE_BYTES]; 5]
            }
            Mode::BlockFinalCommit => fs::write(
                std::path::Path::new(&self.path).join(STAGING_FILE_NAME),
                b"synthetic final commit blocker",
            )
            .unwrap(),
            _ => (),
        }
        Ok(value)
    }
    fn presentation_clock(&self) -> Result<NativePresentationClock, BridgeError> {
        Err(BridgeError::NativeUnavailable)
    }
    fn publish_pending_request(
        &self,
        _: Arc<NativePendingRequest>,
        _: NativeRequestPresentation,
        _: NativeRequestAlert,
    ) -> Result<NativeRequestSinkOutcome, BridgeError> {
        Err(BridgeError::NativeUnavailable)
    }
    fn intake_progress(&self) -> Result<(), BridgeError> {
        Ok(())
    }
    fn advance_approval_drain_for_denial(
        &self,
        _: Arc<NativeDenialScope>,
    ) -> Result<NativeApprovalDrainState, BridgeError> {
        Err(BridgeError::NativeUnavailable)
    }
    fn observe_denial_operation(
        &self,
        _: Arc<NativeDenialAttempt>,
    ) -> Result<NativeDenialOperationState, BridgeError> {
        Err(BridgeError::NativeUnavailable)
    }
    fn release_denial_scope(&self, _: Arc<NativeDenialScope>) -> Result<(), BridgeError> {
        Ok(())
    }
    fn prepare_transport_signer(&self, _: Arc<NativeTransportBinding>) -> Result<(), BridgeError> {
        Err(BridgeError::NativeUnavailable)
    }
    fn sign_client_certificate_verify(
        &self,
        _: Arc<NativeCertificateVerify>,
    ) -> Result<Vec<u8>, BridgeError> {
        Err(BridgeError::NativeUnavailable)
    }
    fn release_transport_signer(&self, _: Arc<NativeTransportBinding>) -> Result<(), BridgeError> {
        Ok(())
    }
    fn state_directory(&self) -> Result<String, BridgeError> {
        Ok(self.path.clone())
    }
    fn clock(&self) -> Result<NativeClock, BridgeError> {
        Ok(NativeClock {
            boot_count: 1,
            monotonic_nanos: 100_000_000,
            weekday: 0,
            minute: 600,
        })
    }
    fn unix_millis(&self) -> Result<u64, BridgeError> {
        Ok(1_700_000_000_000)
    }
    fn legacy_policy_document(&self) -> Result<Option<String>, BridgeError> {
        Ok(None)
    }
    fn has_device_keys(&self) -> Result<bool, BridgeError> {
        Ok(self.created.load(Ordering::Acquire) != 0)
    }
    fn reopen_local_key_sets(&self, _: Vec<NativeLocalKeySet>) -> Result<(), BridgeError> {
        Err(BridgeError::NativeUnavailable)
    }
    fn release_local_key_references(&self) -> Result<(), BridgeError> {
        self.cleanup.fetch_add(1, Ordering::AcqRel);
        if self.cleanup_fails.load(Ordering::Acquire) {
            Err(BridgeError::NativeUnavailable)
        } else {
            Ok(())
        }
    }
    fn clear_request_notifications(&self) -> Result<(), BridgeError> {
        Ok(())
    }
    fn withdraw_requests(&self, _: Vec<NativeRequestSelection>) -> Result<(), BridgeError> {
        Ok(())
    }
}

struct Fixture {
    controller: Arc<MobileController>,
    platform: Arc<Platform>,
    clock: Arc<TestClock>,
    temp: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        Self::with_lease(Arc::new(OwnerLease::acquire().unwrap()))
    }
    // Test-only sharing permits two independent host stores/controllers to
    // exercise pointer identity. Production still acquires one process owner.
    fn with_lease(lease: Arc<OwnerLease>) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let clock = Arc::new(TestClock {
            origin: Instant::now(),
            seconds: AtomicU64::new(1),
            fail: AtomicBool::new(false),
            reads: AtomicU64::new(0),
            stop_on_read: AtomicU64::new(0),
            fail_on_read: AtomicU64::new(0),
            seconds_on_read: Mutex::new(None),
            controller: Mutex::new(Weak::new()),
        });
        let platform = Arc::new(Platform {
            path: temp.path().to_str().unwrap().into(),
            clock: Arc::clone(&clock),
            mode: Mutex::new(Mode::Happy),
            controller: Mutex::new(Weak::new()),
            calls: AtomicUsize::new(0),
            created: AtomicUsize::new(0),
            cleanup: AtomicUsize::new(0),
            cleanup_fails: AtomicBool::new(false),
            saw_preparing: AtomicBool::new(false),
            saw_busy: AtomicBool::new(false),
            request: Mutex::new(None),
        });
        let (boot, reading) = map_clock(platform.clock().unwrap()).unwrap();
        let (owner, _) = DurableInbox::create_fresh_host_model(
            NativePrivateDirectory::from_native_app_data(temp.path()).unwrap(),
            NotificationPolicy::default(),
            CapacityLimits::default(),
            boot,
            reading,
        )
        .unwrap();
        let controller = Arc::new(MobileController {
            platform: platform.clone(),
            boot,
            approval_owner: Mutex::new(Some(
                android_controller::ApprovalPlanOwner::new(&owner, boot).unwrap(),
            )),
            approval_native_plan: Mutex::new(None),
            denial_state: Mutex::new(crate::denial::DenialState::new(&owner, boot).unwrap()),
            projections: Mutex::new(crate::request_projection::ProjectionRegistry::default()),
            intake: Arc::new(crate::intake::IntakeOwner::default()),
            state: Mutex::new(Some(owner)),
            creation_slot: Mutex::new(Weak::<CreationState>::new()),
            approval_alive: Arc::new(AtomicBool::new(true)),
            active: AtomicBool::new(false),
            cleanup_pending: AtomicBool::new(false),
            notification_cleanup_failed: AtomicBool::new(false),
            key_cleanup_pending: AtomicBool::new(false),
            key_cleanup_failed: AtomicBool::new(false),
            native_floor_nanos: AtomicU64::new(reading.phone_monotonic_nanos()),
            _owner_lease: lease,
        });
        *platform.controller.lock().unwrap() = Arc::downgrade(&controller);
        *clock.controller.lock().unwrap() = Arc::downgrade(&controller);
        Self {
            controller,
            platform,
            clock,
            temp,
        }
    }
    fn context(&self, nonce: u8) -> KeyCreationContext {
        KeyCreationContext {
            handle: LocalKeyHandle::from_bytes([1; 32]).unwrap(),
            challenge: LocalAttestationChallenge::from_bytes([65; 32]).unwrap(),
            ceremony_nonce: PairingNonce::from_bytes([nonce; 32]).unwrap(),
            pc: PcIdentity::from_bytes([1; 32]).unwrap(),
            recipient_device: DeviceId::from_bytes([1; 16]).unwrap(),
            pc_signing_key: public(20),
            pc_transport_key: public(21),
            // Synthetic original invitation digest, NOT QR/native proof.
            invitation_context: InvitationContextDigest::from_bytes([71; 32]),
            clock: self.clock.clone(),
            started_at: self.clock.origin,
            deadline: self.clock.origin + MAX_PAIRING_ACCEPTANCE_LIFETIME,
        }
    }
    fn intent(&self) -> KeyCreationIntent {
        self.controller
            .begin_key_creation_from_trusted_host(self.context(2))
            .unwrap()
    }
    fn bytes(&self) -> Vec<u8> {
        fs::read(self.temp.path().join(SNAPSHOT_FILE_NAME)).unwrap()
    }
    fn checkpoint(&self) -> ControllerCheckpoint {
        snapshot(&self.platform.path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.controller.shutdown_native_owner();
    }
}
fn acceptance_fields(created: &CreatedPairingKeys, nonce: u8) -> EnrollmentAcceptanceFields {
    let keys = created.local_keys();
    EnrollmentAcceptanceFields {
        ceremony_nonce: PairingNonce::from_bytes([nonce; 32]).unwrap(),
        attestation_challenge: PairingChallenge::from_bytes(*keys.challenge().as_bytes()).unwrap(),
        pc: PcIdentity::from_bytes([1; 32]).unwrap(),
        recipient_device: DeviceId::from_bytes([1; 16]).unwrap(),
        registry_revision: 1,
        phone_keys: PhoneKeyDigest::from_keys(
            keys.approval_key(),
            keys.denial_key(),
            keys.transport_key(),
        )
        .unwrap(),
        pc_signing_key: public(20),
        pc_transport_key: public(21),
    }
}
fn signed_acceptance(fields: EnrollmentAcceptanceFields, signer: u8) -> Vec<u8> {
    let statement = UnsignedEnrollmentAcceptance::new(fields).unwrap();
    let signature: Signature = SigningKey::from_slice(&[signer; 32])
        .unwrap()
        .sign(&statement.signing_bytes());
    statement
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
        .to_wire()
}
fn signed(created: &CreatedPairingKeys, nonce: u8) -> Vec<u8> {
    signed_acceptance(acceptance_fields(created, nonce), 20)
}
fn frozen_fields(created: &CreatedPairingKeys) -> FrozenCandidateFields {
    let acceptance = acceptance_fields(created, 2);
    FrozenCandidateFields {
        context: FrozenCandidateContext {
            ceremony_nonce: acceptance.ceremony_nonce,
            attestation_challenge: acceptance.attestation_challenge,
            pc: acceptance.pc,
            recipient_device: acceptance.recipient_device,
            phone_keys: acceptance.phone_keys,
            pc_signing_key: acceptance.pc_signing_key,
            pc_transport_key: acceptance.pc_transport_key,
            invitation_context: InvitationContextDigest::from_bytes([71; 32]),
        },
        intended_registry_revision: acceptance.registry_revision,
    }
}
fn signed_frozen(fields: FrozenCandidateFields, signer: u8) -> Vec<u8> {
    let statement = UnsignedFrozenCandidate::new(fields).unwrap();
    let signature: Signature = SigningKey::from_slice(&[signer; 32])
        .unwrap()
        .sign(&statement.signing_bytes());
    statement
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
        .to_wire()
}
fn freeze(f: &Fixture, created: CreatedPairingKeys) -> FrozenCreatedPairing {
    let wire = signed_frozen(frozen_fields(&created), 20);
    f.controller.match_frozen_candidate(created, &wire).unwrap()
}

#[test]
fn preparing_precedes_one_callback_and_created_keys_reuse_real_pending_acceptance_and_reopen() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let f = Fixture::new();
    assert_eq!(bridge_version(), 9);
    let before = f.bytes();
    let intent = f.intent();
    assert_eq!(f.bytes(), before);
    let created = f.controller.create_pairing_keys(intent).unwrap();
    assert_eq!(f.platform.calls.load(Ordering::Acquire), 1);
    assert_eq!(f.platform.created.load(Ordering::Acquire), 1);
    assert!(f.platform.saw_preparing.load(Ordering::Acquire));
    assert!(f.platform.saw_busy.load(Ordering::Acquire));
    assert!(
        f.platform
            .request
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .check_current()
            .is_err()
    );
    assert_eq!(created.local_keys().approval_key(), &public(3));
    assert_eq!(
        created.unverified_evidence().denial.certificates,
        vec![vec![4; 16]]
    );
    assert!(
        f.checkpoint()
            .local_keys()
            .get(created.local_keys().handle())
            .unwrap()
            .descriptor()
            .is_some()
    );
    assert!(f.checkpoint().peer_associations().is_empty());
    assert_eq!(
        f.controller
            .begin_key_creation_from_trusted_host(f.context(3))
            .unwrap_err(),
        BridgeError::InvalidObservation
    );
    let wire = signed(&created, 2);
    let before_freeze = f.bytes();
    let frozen = freeze(&f, created);
    let code = frozen.comparison_code().unwrap();
    assert_eq!(code.as_str().len(), 6);
    assert!(code.as_str().bytes().all(|byte| byte.is_ascii_digit()));
    assert_eq!(f.bytes(), before_freeze);
    let committed = f.controller.commit_created_pairing(frozen, &wire).unwrap();
    assert!(
        f.checkpoint()
            .peer_associations()
            .resolve(committed.association())
            .is_some()
    );
    f.controller.shutdown_native_owner().unwrap();
    let (boot, clock) = map_clock(f.platform.clock().unwrap()).unwrap();
    let (reopened, _) = DurableInbox::open_existing_host_model(
        NativePrivateDirectory::from_native_app_data(f.temp.path()).unwrap(),
        boot,
        clock,
    )
    .unwrap();
    assert!(
        reopened
            .peer_associations()
            .unwrap()
            .resolve(committed.association())
            .is_some()
    );
    assert!(
        reopened
            .local_keys()
            .unwrap()
            .get(LocalKeyHandle::from_bytes([1; 32]).unwrap())
            .unwrap()
            .descriptor()
            .is_some()
    );
}

#[test]
fn dropping_or_cancelling_unprepared_intent_never_writes_or_creates() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let f = Fixture::new();
    let before = f.bytes();
    let intent = f.intent();
    assert_eq!(
        f.controller
            .begin_key_creation_from_trusted_host(f.context(3))
            .unwrap_err(),
        BridgeError::Busy
    );
    drop(intent);
    let next = f
        .controller
        .begin_key_creation_from_trusted_host(f.context(4))
        .unwrap();
    next.cancel();
    assert_eq!(
        f.controller.create_pairing_keys(next).unwrap_err(),
        BridgeError::Closed
    );
    drop(
        f.controller
            .begin_key_creation_from_trusted_host(f.context(5))
            .unwrap(),
    );
    assert_eq!(f.bytes(), before);
    assert_eq!(f.platform.calls.load(Ordering::Acquire), 0);
}

#[test]
fn expired_or_unavailable_original_clock_before_preparing_consumes_without_write() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for fail in [false, true] {
        let f = Fixture::new();
        let before = f.bytes();
        let intent = f.intent();
        if fail {
            f.clock.fail.store(true, Ordering::Release);
        } else {
            f.clock.seconds.store(301, Ordering::Release);
        }
        assert!(f.controller.create_pairing_keys(intent).is_err());
        assert_eq!(f.bytes(), before);
        assert_eq!(f.platform.calls.load(Ordering::Acquire), 0);
        assert!(
            f.controller
                .creation_slot
                .lock()
                .unwrap()
                .upgrade()
                .is_none()
        );
    }
}

#[test]
fn invalid_factory_lifetime_and_existing_local_identity_never_create_again() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let f = Fixture::new();
    let before = f.bytes();
    for seconds in [0, 301] {
        let mut context = f.context(2);
        context.deadline = context.started_at + Duration::from_secs(seconds);
        assert_eq!(
            f.controller
                .begin_key_creation_from_trusted_host(context)
                .unwrap_err(),
            BridgeError::InvalidObservation
        );
    }
    assert_eq!(f.bytes(), before);
    let created = f.controller.create_pairing_keys(f.intent()).unwrap();
    let after = f.bytes();
    drop(created);
    f.platform.request.lock().unwrap().take();
    assert_eq!(
        f.controller
            .begin_key_creation_from_trusted_host(f.context(3))
            .unwrap_err(),
        BridgeError::InvalidObservation
    );
    assert_eq!(f.bytes(), after);
    assert_eq!(f.platform.calls.load(Ordering::Acquire), 1);
}

#[test]
fn receiving_domain_fault_blocks_the_original_creation_intent_before_native_work() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let f = Fixture::new();
    let intent = f.intent();
    {
        let _admission = f.controller.enter().unwrap();
        f.controller
            .with_inbox(|owner| {
                let mut sample = f.platform.clock()?;
                sample.monotonic_nanos = 99_000_000;
                let _ = owner
                    .poll(map_clock(sample)?.1)
                    .map_err(|_| BridgeError::StorageUnavailable)?;
                Ok(())
            })
            .unwrap();
    }
    assert_eq!(
        f.controller.create_pairing_keys(intent).unwrap_err(),
        BridgeError::OwnerFaulted
    );
    assert_eq!(f.platform.calls.load(Ordering::Acquire), 0);
    assert!(f.checkpoint().local_keys().is_empty());
}

#[test]
fn late_callback_and_native_reply_failures_preserve_preparing_without_retry() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for mode in [
        Mode::ErrorBeforeTake,
        Mode::ErrorAfterTake,
        Mode::NoTake,
        Mode::ExpireBeforeTake,
        Mode::ExpireAfterReply,
        Mode::RegressBeforeTake,
        Mode::ClockFailsBeforeTake,
        Mode::ClockFailsAfterReply,
    ] {
        let f = Fixture::new();
        *f.platform.mode.lock().unwrap() = mode;
        let intent = f.intent();
        assert_eq!(
            f.controller.create_pairing_keys(intent).unwrap_err(),
            BridgeError::LocalKeysReconciliationRequired
        );
        assert_eq!(f.platform.calls.load(Ordering::Acquire), 1);
        assert!(f.platform.saw_preparing.load(Ordering::Acquire));
        if matches!(
            mode,
            Mode::ExpireBeforeTake
                | Mode::RegressBeforeTake
                | Mode::ClockFailsBeforeTake
                | Mode::ErrorBeforeTake
                | Mode::NoTake
        ) {
            assert_eq!(f.platform.created.load(Ordering::Acquire), 0);
        }
        assert!(matches!(
            f.checkpoint().local_keys().entries().next(),
            Some(LocalKeySetPhase::Preparing { .. })
        ));
        assert!(f.controller.state.lock().unwrap().is_none());
        assert!(
            f.controller
                .begin_key_creation_from_trusted_host(f.context(3))
                .is_err()
        );
        assert!(
            f.platform
                .request
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .take_input()
                .is_err()
        );
        assert_eq!(f.platform.calls.load(Ordering::Acquire), 1);
    }
}

#[test]
fn native_stop_during_creation_returns_no_live_result_and_preserves_preparing() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let f = Fixture::new();
    *f.platform.mode.lock().unwrap() = Mode::StopAfterReply;
    assert_eq!(
        f.controller.create_pairing_keys(f.intent()).unwrap_err(),
        BridgeError::Closed
    );
    assert!(matches!(
        f.checkpoint().local_keys().entries().next(),
        Some(LocalKeySetPhase::Preparing { .. })
    ));
    assert_eq!(f.platform.created.load(Ordering::Acquire), 1);
    assert!(f.controller.state.lock().unwrap().is_none());
}

#[test]
fn created_result_keeps_the_single_slot_until_all_closed_handles_are_dropped() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let f = Fixture::new();
    let created = f.controller.create_pairing_keys(f.intent()).unwrap();
    let other_context = || {
        let mut context = f.context(3);
        context.handle = LocalKeyHandle::from_bytes([2; 32]).unwrap();
        context.challenge = LocalAttestationChallenge::from_bytes([66; 32]).unwrap();
        context.pc = PcIdentity::from_bytes([2; 32]).unwrap();
        context.pc_signing_key = public(22);
        context.pc_transport_key = public(23);
        context
    };
    let before = f.bytes();
    assert_eq!(
        f.controller
            .begin_key_creation_from_trusted_host(other_context())
            .unwrap_err(),
        BridgeError::Busy
    );
    drop(created);
    assert_eq!(
        f.controller
            .begin_key_creation_from_trusted_host(other_context())
            .unwrap_err(),
        BridgeError::Busy
    );
    f.platform.request.lock().unwrap().take();
    drop(
        f.controller
            .begin_key_creation_from_trusted_host(other_context())
            .unwrap(),
    );
    assert_eq!(f.bytes(), before);
    assert_eq!(f.platform.calls.load(Ordering::Acquire), 1);
}

#[test]
fn wrong_echo_roles_spki_and_evidence_bounds_do_not_commit_created_metadata() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for mode in [
        Mode::WrongHandle,
        Mode::WrongChallenge,
        Mode::WrongNonce,
        Mode::DuplicateKey,
        Mode::PcKeyAsPhoneKey,
        Mode::InvalidSpki,
        Mode::EmptyChain,
        Mode::TooManyCertificates,
        Mode::LargeCertificate,
        Mode::LargeChain,
    ] {
        let f = Fixture::new();
        *f.platform.mode.lock().unwrap() = mode;
        assert_eq!(
            f.controller.create_pairing_keys(f.intent()).unwrap_err(),
            BridgeError::LocalKeysReconciliationRequired
        );
        assert!(matches!(
            f.checkpoint().local_keys().entries().next(),
            Some(LocalKeySetPhase::Preparing { .. })
        ));
        assert!(f.checkpoint().peer_associations().is_empty());
        assert_eq!(f.platform.calls.load(Ordering::Acquire), 1);
    }
}

#[test]
fn real_preparing_or_final_store_failure_never_reports_created_or_rolls_back() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for after_native in [false, true] {
        let f = Fixture::new();
        let intent = f.intent();
        if after_native {
            *f.platform.mode.lock().unwrap() = Mode::BlockFinalCommit;
        } else {
            fs::write(
                f.temp.path().join(STAGING_FILE_NAME),
                b"synthetic preparing blocker",
            )
            .unwrap();
        }
        assert!(f.controller.create_pairing_keys(intent).is_err());
        assert_eq!(
            f.platform.calls.load(Ordering::Acquire),
            usize::from(after_native)
        );
        assert!(f.controller.state.lock().unwrap().is_none());
        assert!(f.checkpoint().peer_associations().is_empty());
        // No deletion/reopen/rollback assertion; these explicit early blockers
        // are not claims about bytes following an arbitrary uncertain flush.
    }
}

#[test]
fn caught_callback_unwind_closes_request_and_preserves_reconciliation_cleanup_obligation() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let f = Fixture::new();
    *f.platform.mode.lock().unwrap() = Mode::PanicAfterTake;
    let intent = f.intent();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f
            .controller
            .create_pairing_keys(intent)))
        .is_err()
    );
    assert!(f.controller.state.lock().unwrap().is_none());
    assert!(f.controller.key_cleanup_pending.load(Ordering::Acquire));
    assert!(
        f.platform
            .request
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .check_current()
            .is_err()
    );
    assert!(matches!(
        f.checkpoint().local_keys().entries().next(),
        Some(LocalKeySetPhase::Preparing { .. })
    ));
    f.controller.shutdown_native_owner().unwrap();
}

#[test]
fn failed_memory_cleanup_remains_owned_until_explicit_shutdown_retry() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let f = Fixture::new();
    f.platform.cleanup_fails.store(true, Ordering::Release);
    *f.platform.mode.lock().unwrap() = Mode::ErrorAfterTake;
    assert!(f.controller.create_pairing_keys(f.intent()).is_err());
    assert!(f.controller.key_cleanup_pending.load(Ordering::Acquire));
    assert!(f.controller.key_cleanup_failed.load(Ordering::Acquire));
    let attempts = f.platform.cleanup.load(Ordering::Acquire);
    assert!(f.controller.continue_native_cleanup().is_err());
    assert_eq!(f.platform.cleanup.load(Ordering::Acquire), attempts);
    f.platform.cleanup_fails.store(false, Ordering::Release);
    f.controller.shutdown_native_owner().unwrap();
    assert!(!f.controller.key_cleanup_pending.load(Ordering::Acquire));
}

#[test]
fn new_owner_cannot_consume_old_intent() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let old = Fixture::new();
    let intent = old.intent();
    drop(old);
    let next = Fixture::new();
    let before = next.bytes();
    assert_eq!(
        next.controller.create_pairing_keys(intent).unwrap_err(),
        BridgeError::InvalidObservation
    );
    assert_eq!(next.bytes(), before);
    assert_eq!(next.platform.calls.load(Ordering::Acquire), 0);
}

#[test]
fn dropped_created_result_leaves_metadata_and_old_signed_receipt_cannot_rebind_nonce() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let f = Fixture::new();
    let created = f.controller.create_pairing_keys(f.intent()).unwrap();
    let before = f.bytes();
    let wrong = signed(&created, 99);
    let frozen = freeze(&f, created);
    assert!(f.controller.commit_created_pairing(frozen, &wrong).is_err());
    assert_eq!(f.bytes(), before);
    assert!(
        f.checkpoint()
            .local_keys()
            .entries()
            .next()
            .unwrap()
            .descriptor()
            .is_some()
    );
    assert!(f.checkpoint().peer_associations().is_empty());
    f.platform.request.lock().unwrap().take();
    assert!(
        f.controller
            .creation_slot
            .lock()
            .unwrap()
            .upgrade()
            .is_none()
    );
    assert_eq!(f.platform.calls.load(Ordering::Acquire), 1);
}

#[test]
fn acceptance_receive_and_precommit_reads_observe_original_creation_stop() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    // Entry is read1, post-frozen-binding read2, core receive read3, and final
    // core precommit read4. Each observes the SAME original creation clock.
    for stop_at in [2, 3, 4] {
        let f = Fixture::new();
        let created = f.controller.create_pairing_keys(f.intent()).unwrap();
        let wire = signed(&created, 2);
        let frozen = freeze(&f, created);
        let before = f.bytes();
        let previous = f.clock.reads.load(Ordering::Acquire);
        f.clock
            .stop_on_read
            .store(previous + stop_at, Ordering::Release);
        let error = f
            .controller
            .commit_created_pairing(frozen, &wire)
            .unwrap_err();
        assert!(matches!(error, CreatedPairingCommitError::Rejected(_)));
        assert_eq!(f.clock.reads.load(Ordering::Acquire), previous + stop_at);
        assert_eq!(f.bytes(), before);
        assert!(f.checkpoint().peer_associations().is_empty());
        assert_eq!(f.checkpoint().peer_associations().next_generation(), 1);
    }
}

#[test]
fn post_commit_stop_returns_the_real_receipt_without_claiming_live_success_or_rollback() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let f = Fixture::new();
    let created = f.controller.create_pairing_keys(f.intent()).unwrap();
    let wire = signed(&created, 2);
    let frozen = freeze(&f, created);
    let before = f.bytes();
    let previous = f.clock.reads.load(Ordering::Acquire);
    f.clock.stop_on_read.store(previous + 5, Ordering::Release);
    let error = f
        .controller
        .commit_created_pairing(frozen, &wire)
        .unwrap_err();
    let CreatedPairingCommitError::CommittedButNotLive { committed, cause } = error else {
        panic!("the confirmed commit must remain observable");
    };
    assert_eq!(cause, BridgeError::Closed);
    assert_eq!(f.clock.reads.load(Ordering::Acquire), previous + 5);
    assert_ne!(f.bytes(), before);
    assert!(
        f.checkpoint()
            .peer_associations()
            .resolve(committed.association())
            .is_some()
    );
    assert_eq!(f.checkpoint().peer_associations().next_generation(), 2);
}

#[test]
fn creation_clock_returns_exactly_the_one_original_sample_and_rejects_dropped_origin() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let f = Fixture::new();
    let intent = f.intent();
    let guarded = CreationClock {
        state: Arc::downgrade(&intent.state),
    };
    f.clock.seconds.store(23, Ordering::Release);
    let previous = f.clock.reads.load(Ordering::Acquire);
    assert_eq!(
        guarded.now().unwrap(),
        f.clock.origin + Duration::from_secs(23)
    );
    assert_eq!(f.clock.reads.load(Ordering::Acquire), previous + 1);
    drop(intent);
    assert!(guarded.now().is_err());
    assert_eq!(f.clock.reads.load(Ordering::Acquire), previous + 1);
}

fn assert_created_only_unchanged(f: &Fixture, before: &[u8]) {
    assert_eq!(f.bytes(), before);
    let checkpoint = f.checkpoint();
    assert!(matches!(
        checkpoint.local_keys().entries().next(),
        Some(LocalKeySetPhase::CreatedUnverified(_))
    ));
    assert!(checkpoint.peer_associations().is_empty());
    assert_eq!(checkpoint.peer_associations().next_generation(), 1);
    assert_eq!(f.platform.calls.load(Ordering::Acquire), 1);
    assert_eq!(f.platform.created.load(Ordering::Acquire), 1);
}

#[derive(Clone, Copy, Debug)]
enum ContextMismatch {
    Invitation,
    Recipient,
    Nonce,
    Challenge,
    Pc,
    Approval,
    Denial,
    Transport,
    RoleOrder,
    SigningPin,
    TransportPin,
    BothPins,
}
fn change_context(context: &mut FrozenCandidateContext, mismatch: ContextMismatch) -> u8 {
    match mismatch {
        ContextMismatch::Invitation => {
            context.invitation_context = InvitationContextDigest::from_bytes([99; 32]);
        }
        ContextMismatch::Recipient => {
            context.recipient_device = DeviceId::from_bytes([99; 16]).unwrap();
        }
        ContextMismatch::Nonce => {
            context.ceremony_nonce = PairingNonce::from_bytes([99; 32]).unwrap();
        }
        ContextMismatch::Challenge => {
            context.attestation_challenge = PairingChallenge::from_bytes([99; 32]).unwrap();
        }
        ContextMismatch::Pc => context.pc = PcIdentity::from_bytes([99; 32]).unwrap(),
        ContextMismatch::Approval => {
            context.phone_keys =
                PhoneKeyDigest::from_keys(&public(6), &public(4), &public(5)).unwrap();
        }
        ContextMismatch::Denial => {
            context.phone_keys =
                PhoneKeyDigest::from_keys(&public(3), &public(6), &public(5)).unwrap();
        }
        ContextMismatch::Transport => {
            context.phone_keys =
                PhoneKeyDigest::from_keys(&public(3), &public(4), &public(6)).unwrap();
        }
        ContextMismatch::RoleOrder => {
            context.phone_keys =
                PhoneKeyDigest::from_keys(&public(4), &public(3), &public(5)).unwrap();
        }
        ContextMismatch::SigningPin => context.pc_signing_key = public(22),
        ContextMismatch::TransportPin => context.pc_transport_key = public(23),
        ContextMismatch::BothPins => {
            context.pc_signing_key = public(22);
            context.pc_transport_key = public(23);
        }
    }
    if matches!(
        mismatch,
        ContextMismatch::SigningPin | ContextMismatch::BothPins
    ) {
        // Self-consistent attacker pin/signature still cannot replace the
        // separately retained original pin.
        22
    } else {
        20
    }
}

fn acceptance_from_frozen(fields: &FrozenCandidateFields) -> EnrollmentAcceptanceFields {
    let context = &fields.context;
    EnrollmentAcceptanceFields {
        ceremony_nonce: context.ceremony_nonce,
        attestation_challenge: context.attestation_challenge,
        pc: context.pc,
        recipient_device: context.recipient_device,
        registry_revision: fields.intended_registry_revision,
        phone_keys: context.phone_keys,
        pc_signing_key: context.pc_signing_key.clone(),
        pc_transport_key: context.pc_transport_key.clone(),
    }
}

#[test]
fn frozen_signature_never_supplies_its_own_original_context_or_role_tuple() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for mismatch in [
        ContextMismatch::Invitation,
        ContextMismatch::Recipient,
        ContextMismatch::Nonce,
        ContextMismatch::Challenge,
        ContextMismatch::Pc,
        ContextMismatch::Approval,
        ContextMismatch::Denial,
        ContextMismatch::Transport,
        ContextMismatch::RoleOrder,
        ContextMismatch::SigningPin,
        ContextMismatch::TransportPin,
        ContextMismatch::BothPins,
    ] {
        let f = Fixture::new();
        let created = f.controller.create_pairing_keys(f.intent()).unwrap();
        let before = f.bytes();
        let mut fields = frozen_fields(&created);
        let signer = change_context(&mut fields.context, mismatch);
        let wire = signed_frozen(fields, signer);
        assert_eq!(
            f.controller
                .match_frozen_candidate(created, &wire)
                .unwrap_err(),
            BridgeError::InvalidObservation,
            "{mismatch:?}"
        );
        assert_created_only_unchanged(&f, &before);
        f.platform.request.lock().unwrap().take();
        assert!(
            f.controller
                .creation_slot
                .lock()
                .unwrap()
                .upgrade()
                .is_none()
        );
    }
}

#[test]
fn frozen_wrong_signer_malformed_truncated_and_revision_tampering_never_commit() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    // Revision is PC-assigned and signed, not a phone-selected expectation.
    // Test invalid endpoints and a changed valid revision without a new signature.
    enum Defect {
        WrongSigner,
        Empty,
        HeaderOnly,
        MissingLastByte,
        TrailingByte,
        Oversized,
        Magic,
        Signature,
        ZeroRevision,
        ExhaustedRevision,
        ChangedRevision,
        AcceptanceInsteadOfFrozen,
    }
    for defect in [
        Defect::WrongSigner,
        Defect::Empty,
        Defect::HeaderOnly,
        Defect::MissingLastByte,
        Defect::TrailingByte,
        Defect::Oversized,
        Defect::Magic,
        Defect::Signature,
        Defect::ZeroRevision,
        Defect::ExhaustedRevision,
        Defect::ChangedRevision,
        Defect::AcceptanceInsteadOfFrozen,
    ] {
        let f = Fixture::new();
        let created = f.controller.create_pairing_keys(f.intent()).unwrap();
        let before = f.bytes();
        let mut wire = signed_frozen(frozen_fields(&created), 20);
        const REVISION_OFFSET: usize = 12 + 32 + 32 + 32 + 16;
        match defect {
            Defect::WrongSigner => wire = signed_frozen(frozen_fields(&created), 22),
            Defect::Empty => wire.clear(),
            Defect::HeaderOnly => wire.truncate(12),
            Defect::MissingLastByte => {
                wire.pop();
            }
            Defect::TrailingByte => wire.push(0),
            Defect::Oversized => wire = vec![0; MAX_FROZEN_CANDIDATE_BYTES + 1],
            Defect::Magic => wire[0] ^= 1,
            Defect::Signature => *wire.last_mut().unwrap() ^= 1,
            Defect::ZeroRevision => {
                wire[REVISION_OFFSET..REVISION_OFFSET + 8].copy_from_slice(&0u64.to_be_bytes());
            }
            Defect::ExhaustedRevision => {
                wire[REVISION_OFFSET..REVISION_OFFSET + 8].copy_from_slice(&u64::MAX.to_be_bytes());
            }
            Defect::ChangedRevision => {
                wire[REVISION_OFFSET..REVISION_OFFSET + 8].copy_from_slice(&2u64.to_be_bytes());
            }
            Defect::AcceptanceInsteadOfFrozen => wire = signed(&created, 2),
        }
        assert_eq!(
            f.controller
                .match_frozen_candidate(created, &wire)
                .unwrap_err(),
            BridgeError::InvalidObservation
        );
        assert_created_only_unchanged(&f, &before);
    }
}

#[derive(Clone, Copy)]
enum ClockLoss {
    Stop,
    Expiry,
    Regression,
    Unavailable,
}
fn lose_clock_at(f: &Fixture, read: u64, loss: ClockLoss) {
    match loss {
        ClockLoss::Stop => f.clock.stop_on_read.store(read, Ordering::Release),
        ClockLoss::Expiry => *f.clock.seconds_on_read.lock().unwrap() = Some((read, 300)),
        ClockLoss::Regression => *f.clock.seconds_on_read.lock().unwrap() = Some((read, 0)),
        ClockLoss::Unavailable => f.clock.fail_on_read.store(read, Ordering::Release),
    }
}

#[test]
fn frozen_matching_rechecks_original_liveness_before_and_after_verification() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for boundary in [1, 2] {
        for loss in [
            ClockLoss::Stop,
            ClockLoss::Expiry,
            ClockLoss::Regression,
            ClockLoss::Unavailable,
        ] {
            let f = Fixture::new();
            let created = f.controller.create_pairing_keys(f.intent()).unwrap();
            let wire = signed_frozen(frozen_fields(&created), 20);
            let before = f.bytes();
            let previous = f.clock.reads.load(Ordering::Acquire);
            lose_clock_at(&f, previous + boundary, loss);
            assert!(f.controller.match_frozen_candidate(created, &wire).is_err());
            assert_eq!(f.clock.reads.load(Ordering::Acquire), previous + boundary);
            assert_created_only_unchanged(&f, &before);
        }
    }
}

#[test]
fn comparison_code_is_checked_live_at_both_boundaries_and_never_revives() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for boundary in [1, 2] {
        for loss in [
            ClockLoss::Stop,
            ClockLoss::Expiry,
            ClockLoss::Regression,
            ClockLoss::Unavailable,
        ] {
            let f = Fixture::new();
            let created = f.controller.create_pairing_keys(f.intent()).unwrap();
            let frozen = freeze(&f, created);
            let before = f.bytes();
            let previous = f.clock.reads.load(Ordering::Acquire);
            lose_clock_at(&f, previous + boundary, loss);
            assert!(frozen.comparison_code().is_err());
            assert_eq!(f.clock.reads.load(Ordering::Acquire), previous + boundary);
            f.clock.seconds.store(1, Ordering::Release);
            f.clock.fail.store(false, Ordering::Release);
            assert!(frozen.comparison_code().is_err());
            assert_created_only_unchanged(&f, &before);
        }
    }
}

#[test]
fn final_acceptance_original_clock_loss_before_commit_never_mutates() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for boundary in [1, 2, 3, 4] {
        for loss in [
            ClockLoss::Expiry,
            ClockLoss::Regression,
            ClockLoss::Unavailable,
        ] {
            let f = Fixture::new();
            let created = f.controller.create_pairing_keys(f.intent()).unwrap();
            let wire = signed(&created, 2);
            let frozen = freeze(&f, created);
            let before = f.bytes();
            let previous = f.clock.reads.load(Ordering::Acquire);
            lose_clock_at(&f, previous + boundary, loss);
            assert!(matches!(
                f.controller.commit_created_pairing(frozen, &wire),
                Err(CreatedPairingCommitError::Rejected(_))
            ));
            assert_eq!(f.clock.reads.load(Ordering::Acquire), previous + boundary);
            assert_created_only_unchanged(&f, &before);
        }
    }
}

#[test]
fn post_commit_clock_loss_keeps_the_actual_local_receipt() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for loss in [
        ClockLoss::Expiry,
        ClockLoss::Regression,
        ClockLoss::Unavailable,
    ] {
        let f = Fixture::new();
        let created = f.controller.create_pairing_keys(f.intent()).unwrap();
        let wire = signed(&created, 2);
        let frozen = freeze(&f, created);
        let before = f.bytes();
        let previous = f.clock.reads.load(Ordering::Acquire);
        lose_clock_at(&f, previous + 5, loss);
        let error = f
            .controller
            .commit_created_pairing(frozen, &wire)
            .unwrap_err();
        let CreatedPairingCommitError::CommittedButNotLive { committed, cause } = error else {
            panic!("the confirmed local receipt must survive late clock loss");
        };
        assert_eq!(
            cause,
            match loss {
                ClockLoss::Unavailable => BridgeError::NativeUnavailable,
                _ => BridgeError::InvalidObservation,
            }
        );
        assert_eq!(f.clock.reads.load(Ordering::Acquire), previous + 5);
        assert_ne!(f.bytes(), before);
        assert!(
            f.checkpoint()
                .peer_associations()
                .resolve(committed.association())
                .is_some()
        );
        assert_eq!(f.checkpoint().peer_associations().next_generation(), 2);
    }
}

#[test]
fn cancellation_before_or_after_freeze_never_yields_a_code_or_acceptance() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for after_freeze in [false, true] {
        let f = Fixture::new();
        let created = f.controller.create_pairing_keys(f.intent()).unwrap();
        let before = f.bytes();
        if after_freeze {
            let wire = signed(&created, 2);
            let frozen = freeze(&f, created);
            frozen.cancel();
            assert_eq!(frozen.comparison_code().unwrap_err(), BridgeError::Closed);
            assert!(matches!(
                f.controller.commit_created_pairing(frozen, &wire),
                Err(CreatedPairingCommitError::Rejected(BridgeError::Closed))
            ));
        } else {
            let wire = signed_frozen(frozen_fields(&created), 20);
            created.cancel();
            assert_eq!(
                f.controller
                    .match_frozen_candidate(created, &wire)
                    .unwrap_err(),
                BridgeError::Closed
            );
        }
        assert_created_only_unchanged(&f, &before);
    }
}

#[test]
fn another_live_controller_cannot_match_or_commit_an_original_candidate() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for after_freeze in [false, true] {
        let f = Fixture::new();
        let created = f.controller.create_pairing_keys(f.intent()).unwrap();
        let other = Fixture::with_lease(Arc::clone(&f.controller._owner_lease));
        let original_before = f.bytes();
        let other_before = other.bytes();
        if after_freeze {
            let wire = signed(&created, 2);
            let frozen = freeze(&f, created);
            assert!(matches!(
                other.controller.commit_created_pairing(frozen, &wire),
                Err(CreatedPairingCommitError::Rejected(
                    BridgeError::InvalidObservation
                ))
            ));
        } else {
            let wire = signed_frozen(frozen_fields(&created), 20);
            assert_eq!(
                other
                    .controller
                    .match_frozen_candidate(created, &wire)
                    .unwrap_err(),
                BridgeError::InvalidObservation
            );
        }
        assert_created_only_unchanged(&f, &original_before);
        assert_eq!(other.bytes(), other_before);
        assert_eq!(other.platform.calls.load(Ordering::Acquire), 0);
    }
}

#[test]
fn dropped_controller_cannot_leave_frozen_comparison_metadata_live() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let old = Fixture::new();
    let created = old.controller.create_pairing_keys(old.intent()).unwrap();
    let wire = signed(&created, 2);
    let frozen = freeze(&old, created);
    drop(old);
    assert_eq!(frozen.comparison_code().unwrap_err(), BridgeError::Closed);
    let next = Fixture::new();
    let before = next.bytes();
    assert!(matches!(
        next.controller.commit_created_pairing(frozen, &wire),
        Err(CreatedPairingCommitError::Rejected(
            BridgeError::InvalidObservation
        ))
    ));
    assert_eq!(next.bytes(), before);
    assert_eq!(next.platform.calls.load(Ordering::Acquire), 0);
}

#[test]
fn every_final_acceptance_binding_must_match_the_retained_frozen_candidate() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for mismatch in [
        ContextMismatch::Recipient,
        ContextMismatch::Nonce,
        ContextMismatch::Challenge,
        ContextMismatch::Pc,
        ContextMismatch::Approval,
        ContextMismatch::Denial,
        ContextMismatch::Transport,
        ContextMismatch::RoleOrder,
        ContextMismatch::SigningPin,
        ContextMismatch::TransportPin,
        ContextMismatch::BothPins,
    ] {
        let f = Fixture::new();
        let created = f.controller.create_pairing_keys(f.intent()).unwrap();
        let mut fields = frozen_fields(&created);
        let frozen = freeze(&f, created);
        let before = f.bytes();
        let signer = change_context(&mut fields.context, mismatch);
        let wire = signed_acceptance(acceptance_from_frozen(&fields), signer);
        assert!(
            matches!(
                f.controller.commit_created_pairing(frozen, &wire),
                Err(CreatedPairingCommitError::Rejected(
                    BridgeError::InvalidObservation
                ))
            ),
            "{mismatch:?}"
        );
        assert_created_only_unchanged(&f, &before);
    }
}

#[test]
fn final_acceptance_wrong_revision_signature_or_wire_is_rejected_before_commit() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for defect in 0..4 {
        let f = Fixture::new();
        let created = f.controller.create_pairing_keys(f.intent()).unwrap();
        let mut fields = acceptance_fields(&created, 2);
        let frozen_wire = signed_frozen(frozen_fields(&created), 20);
        let frozen = freeze(&f, created);
        let before = f.bytes();
        let wire = match defect {
            0 => {
                fields.registry_revision = 2;
                signed_acceptance(fields, 20)
            }
            1 => signed_acceptance(fields, 22),
            2 => Vec::new(),
            3 => frozen_wire,
            _ => unreachable!(),
        };
        assert!(matches!(
            f.controller.commit_created_pairing(frozen, &wire),
            Err(CreatedPairingCommitError::Rejected(
                BridgeError::InvalidObservation
            ))
        ));
        assert_created_only_unchanged(&f, &before);
    }
}

#[test]
fn original_nondefault_context_and_pc_selected_revision_are_retained_without_reassignment() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let f = Fixture::new();
    let mut context = f.context(37);
    context.pc = PcIdentity::from_bytes([44; 32]).unwrap();
    context.recipient_device = DeviceId::from_bytes([42; 16]).unwrap();
    context.pc_signing_key = public(22);
    context.pc_transport_key = public(23);
    context.invitation_context = InvitationContextDigest::from_bytes([43; 32]);
    let intent = f
        .controller
        .begin_key_creation_from_trusted_host(context)
        .unwrap();
    let created = f.controller.create_pairing_keys(intent).unwrap();
    let mut fields = frozen_fields(&created);
    fields.context.ceremony_nonce = PairingNonce::from_bytes([37; 32]).unwrap();
    fields.context.pc = PcIdentity::from_bytes([44; 32]).unwrap();
    fields.context.recipient_device = DeviceId::from_bytes([42; 16]).unwrap();
    fields.context.pc_signing_key = public(22);
    fields.context.pc_transport_key = public(23);
    fields.context.invitation_context = InvitationContextDigest::from_bytes([43; 32]);
    fields.intended_registry_revision = 41;
    let acceptance = signed_acceptance(acceptance_from_frozen(&fields), 22);
    let wire = signed_frozen(fields.clone(), 22);
    let expected_code = SignedFrozenCandidate::from_wire(&wire)
        .unwrap()
        .verify(&public(22))
        .unwrap()
        .match_original(&fields.context)
        .unwrap()
        .comparison_code();
    let before = f.bytes();
    let frozen = f.controller.match_frozen_candidate(created, &wire).unwrap();
    assert_eq!(frozen.comparison_code().unwrap(), expected_code);
    assert_eq!(f.bytes(), before);
    let committed = f
        .controller
        .commit_created_pairing(frozen, &acceptance)
        .unwrap();
    let checkpoint = f.checkpoint();
    let association = checkpoint
        .peer_associations()
        .resolve(committed.association())
        .unwrap();
    assert_eq!(
        association.descriptor().recipient_device_id(),
        fields.context.recipient_device
    );
    assert_eq!(association.descriptor().pc_registry_revision(), 41);
}

#[test]
fn frozen_wrapper_retains_the_same_slot_and_redacts_code_and_context() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let f = Fixture::new();
    let created = f.controller.create_pairing_keys(f.intent()).unwrap();
    let frozen = freeze(&f, created);
    let before = f.bytes();
    assert_eq!(
        format!("{frozen:?}"),
        "FrozenCreatedPairing([redacted], matched_not_paired)"
    );
    assert_eq!(
        format!("{:?}", frozen.comparison_code().unwrap()),
        "PairingComparisonCode([redacted], public_comparison_only)"
    );
    let other_context = || {
        let mut context = f.context(3);
        context.handle = LocalKeyHandle::from_bytes([2; 32]).unwrap();
        context.challenge = LocalAttestationChallenge::from_bytes([66; 32]).unwrap();
        context.pc = PcIdentity::from_bytes([2; 32]).unwrap();
        context.pc_signing_key = public(22);
        context.pc_transport_key = public(23);
        context
    };
    assert_eq!(
        f.controller
            .begin_key_creation_from_trusted_host(other_context())
            .unwrap_err(),
        BridgeError::Busy
    );
    drop(frozen);
    assert_eq!(
        f.controller
            .begin_key_creation_from_trusted_host(other_context())
            .unwrap_err(),
        BridgeError::Busy
    );
    f.platform.request.lock().unwrap().take();
    drop(
        f.controller
            .begin_key_creation_from_trusted_host(other_context())
            .unwrap(),
    );
    assert_created_only_unchanged(&f, &before);
}

#[test]
fn frozen_acceptance_storage_failure_preserves_the_existing_uncertain_owner_contract() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let f = Fixture::new();
    let created = f.controller.create_pairing_keys(f.intent()).unwrap();
    let wire = signed(&created, 2);
    let frozen = freeze(&f, created);
    fs::write(
        f.temp.path().join(STAGING_FILE_NAME),
        b"synthetic acceptance blocker",
    )
    .unwrap();
    assert!(matches!(
        f.controller.commit_created_pairing(frozen, &wire),
        Err(CreatedPairingCommitError::Rejected(
            BridgeError::StorageUnavailable
        ))
    ));
    assert!(f.controller.state.lock().unwrap().is_none());
    assert!(!f.controller.approval_alive.load(Ordering::Acquire));
    assert_eq!(f.platform.calls.load(Ordering::Acquire), 1);
    // This explicit early blocker does not characterize an arbitrary failed
    // flush or promise rollback/deletion/recovery of its persistent bytes.
}
