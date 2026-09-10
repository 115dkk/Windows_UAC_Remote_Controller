// SPDX-License-Identifier: GPL-2.0-or-later
//! Real host store/controller composition plus synthetic public key evidence.
//! Callback counters/opaque certificate bytes are NOT Android/attestation QA.

use android_controller::{ControllerCheckpoint, LocalKeySetPhase};
use approval_protocol::DeviceId;
use notification_policy::{CapacityLimits, NotificationPolicy};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use phone_state_store::{
    NativePrivateDirectory, SNAPSHOT_FILE_NAME, STAGING_FILE_NAME, SnapshotStore,
};
use service_protocol::{
    EnrollmentAcceptanceFields, PairingChallenge, PhoneKeyDigest, UnsignedEnrollmentAcceptance,
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
        let temp = tempfile::tempdir().unwrap();
        let clock = Arc::new(TestClock {
            origin: Instant::now(),
            seconds: AtomicU64::new(1),
            fail: AtomicBool::new(false),
            reads: AtomicU64::new(0),
            stop_on_read: AtomicU64::new(0),
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
            creation_slot: Mutex::new(Weak::new()),
            approval_alive: Arc::new(AtomicBool::new(true)),
            active: AtomicBool::new(false),
            cleanup_pending: AtomicBool::new(false),
            notification_cleanup_failed: AtomicBool::new(false),
            key_cleanup_pending: AtomicBool::new(false),
            key_cleanup_failed: AtomicBool::new(false),
            native_floor_nanos: AtomicU64::new(reading.phone_monotonic_nanos()),
            _owner_lease: Arc::new(OwnerLease::acquire().unwrap()),
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
            pc_signing_key: public(20),
            pc_transport_key: public(21),
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
fn signed(created: &CreatedPairingKeys, nonce: u8) -> Vec<u8> {
    let keys = created.local_keys();
    let fields = EnrollmentAcceptanceFields {
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
    };
    let statement = UnsignedEnrollmentAcceptance::new(fields).unwrap();
    let signature: Signature = SigningKey::from_slice(&[20; 32])
        .unwrap()
        .sign(&statement.signing_bytes());
    statement
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
        .to_wire()
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
    let committed = f.controller.commit_created_pairing(created, &wire).unwrap();
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
    assert!(
        f.controller
            .commit_created_pairing(created, &wrong)
            .is_err()
    );
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
    // Commit entry is read1, core receive read2, final core precommit read3.
    for stop_at in [2, 3] {
        let f = Fixture::new();
        let created = f.controller.create_pairing_keys(f.intent()).unwrap();
        let wire = signed(&created, 2);
        let before = f.bytes();
        let previous = f.clock.reads.load(Ordering::Acquire);
        f.clock
            .stop_on_read
            .store(previous + stop_at, Ordering::Release);
        let error = f
            .controller
            .commit_created_pairing(created, &wire)
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
    let before = f.bytes();
    let previous = f.clock.reads.load(Ordering::Acquire);
    f.clock.stop_on_read.store(previous + 4, Ordering::Release);
    let error = f
        .controller
        .commit_created_pairing(created, &wire)
        .unwrap_err();
    let CreatedPairingCommitError::CommittedButNotLive { committed, cause } = error else {
        panic!("the confirmed commit must remain observable");
    };
    assert_eq!(cause, BridgeError::Closed);
    assert_eq!(f.clock.reads.load(Ordering::Acquire), previous + 4);
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
