// SPDX-License-Identifier: GPL-2.0-or-later
//! Real host checkpoint/intent composition with synthetic native clock and lock
//! observations. Not camera, Android Keystore, physical authentication or pairing.

use super::*;
use crate::*;
use android_controller::DurableInbox;
use approval_protocol::{DeviceId, PcIdentity};
use notification_policy::{CapacityLimits, NotificationPolicy};
use p256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};
use phone_state_store::{NativePrivateDirectory, SNAPSHOT_FILE_NAME};
use secure_channel::TlsPublicKey;
use service_protocol::{PairingChallenge, PairingInvitationFields, PairingNonce};
use std::{
    fs,
    sync::{
        atomic::{AtomicU32, AtomicU64, AtomicUsize},
        mpsc,
    },
    time::Duration,
};

struct Platform {
    path: String,
    nanos: AtomicU64,
    boot: AtomicU32,
    secure: AtomicBool,
    clock_failed: AtomicBool,
    key_calls: AtomicUsize,
    hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    fail_after_intent: Mutex<Option<Weak<MobileController>>>,
}
impl NativePlatform for Platform {
    fn secure_lock_configured(&self) -> Result<bool, BridgeError> {
        Ok(self.secure.load(Ordering::Acquire))
    }
    fn presentation_clock(&self) -> Result<NativePresentationClock, BridgeError> {
        let hook = self.hook.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        if self.clock_failed.load(Ordering::Acquire) {
            return Err(BridgeError::NativeUnavailable);
        }
        let owner = self.fail_after_intent.lock().unwrap().clone();
        if owner
            .and_then(|owner| owner.upgrade())
            .is_some_and(|owner| owner.creation_slot.lock().unwrap().upgrade().is_some())
        {
            return Err(BridgeError::NativeUnavailable);
        }
        let nanos = self.nanos.load(Ordering::Acquire);
        Ok(NativePresentationClock {
            boot_count: self.boot.load(Ordering::Acquire),
            elapsed_before_nanos: nanos,
            elapsed_after_nanos: nanos,
            wall_before_millis: 1_700_000_000_000,
            wall_after_millis: 1_700_000_000_000,
            weekday: 0,
            minute: 600,
            millis_within_minute: 0,
            time_epoch: 1,
        })
    }
    fn clock(&self) -> Result<NativeClock, BridgeError> {
        Ok(NativeClock {
            boot_count: self.boot.load(Ordering::Acquire),
            monotonic_nanos: self.nanos.load(Ordering::Acquire),
            weekday: 0,
            minute: 600,
        })
    }
    fn create_local_key_set(
        &self,
        _: Arc<NativeKeyCreationRequest>,
    ) -> Result<NativeCreatedKeyEvidence, BridgeError> {
        self.key_calls.fetch_add(1, Ordering::AcqRel);
        Err(BridgeError::NativeUnavailable)
    }
    fn state_directory(&self) -> Result<String, BridgeError> {
        Ok(self.path.clone())
    }
    fn unix_millis(&self) -> Result<u64, BridgeError> {
        Ok(1_700_000_000_000)
    }
    fn legacy_policy_document(&self) -> Result<Option<String>, BridgeError> {
        Ok(None)
    }
    fn has_device_keys(&self) -> Result<bool, BridgeError> {
        Ok(false)
    }
    fn reopen_local_key_sets(&self, _: Vec<NativeLocalKeySet>) -> Result<(), BridgeError> {
        Err(BridgeError::NativeUnavailable)
    }
    fn release_local_key_references(&self) -> Result<(), BridgeError> {
        Ok(())
    }
    fn clear_request_notifications(&self) -> Result<(), BridgeError> {
        Ok(())
    }
    fn withdraw_requests(&self, _: Vec<NativeRequestSelection>) -> Result<(), BridgeError> {
        Ok(())
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
        Err(BridgeError::NativeUnavailable)
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
        Err(BridgeError::NativeUnavailable)
    }
}
struct Fixture {
    controller: Arc<MobileController>,
    platform: Arc<Platform>,
    temp: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        Self::with_lease(Arc::new(OwnerLease::acquire().unwrap()))
    }
    // Test-only shared lease can exercise wrong-owner identity using separate
    // host stores. Production constructors still enforce one native owner.
    fn with_lease(lease: Arc<OwnerLease>) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let platform = Arc::new(Platform {
            path: temp.path().to_str().unwrap().into(),
            nanos: AtomicU64::new(1_000_000_000),
            boot: AtomicU32::new(1),
            secure: AtomicBool::new(true),
            clock_failed: AtomicBool::new(false),
            key_calls: AtomicUsize::new(0),
            hook: Mutex::new(None),
            fail_after_intent: Mutex::new(None),
        });
        let (boot, clock) = map_clock(platform.clock().unwrap()).unwrap();
        let (inbox, _) = DurableInbox::create_fresh_host_model(
            NativePrivateDirectory::from_native_app_data(temp.path()).unwrap(),
            NotificationPolicy::default(),
            CapacityLimits::default(),
            boot,
            clock,
        )
        .unwrap();
        let controller = Arc::new(MobileController {
            platform: platform.clone(),
            boot,
            approval_owner: Mutex::new(Some(
                android_controller::ApprovalPlanOwner::new(&inbox, boot).unwrap(),
            )),
            approval_alive: Arc::new(AtomicBool::new(true)),
            approval_native_plan: Mutex::new(None),
            denial_state: Mutex::new(crate::denial::DenialState::new(&inbox, boot).unwrap()),
            projections: Mutex::new(crate::request_projection::ProjectionRegistry::default()),
            intake: Arc::new(crate::intake::IntakeOwner::default()),
            state: Mutex::new(Some(inbox)),
            creation_slot: Mutex::new(Weak::<super::super::CreationState>::new()),
            active: AtomicBool::new(false),
            cleanup_pending: AtomicBool::new(false),
            notification_cleanup_failed: AtomicBool::new(false),
            key_cleanup_pending: AtomicBool::new(false),
            key_cleanup_failed: AtomicBool::new(false),
            native_floor_nanos: AtomicU64::new(clock.phone_monotonic_nanos()),
            _owner_lease: lease,
        });
        Self {
            controller,
            platform,
            temp,
        }
    }
    fn bytes(&self) -> Vec<u8> {
        fs::read(self.temp.path().join(SNAPSHOT_FILE_NAME)).unwrap()
    }
    fn legacy_context(&self) -> KeyCreationContext {
        let invitation = invitation();
        let fields = invitation.fields();
        let anchor = ProjectionAnchor::capture(&*self.platform, self.controller.boot).unwrap();
        KeyCreationContext {
            handle: LocalKeyHandle::from_bytes([66; 32]).unwrap(),
            challenge: LocalAttestationChallenge::from_bytes(
                *fields.attestation_challenge.as_bytes(),
            )
            .unwrap(),
            ceremony_nonce: fields.ceremony_nonce,
            pc: fields.pc,
            recipient_device: fields.recipient_device,
            pc_signing_key: fields.pc_signing_key.clone(),
            pc_transport_key: fields.pc_transport_key.clone(),
            invitation_context: invitation.context_digest(),
            started_at: anchor.coordinate(),
            deadline: anchor.coordinate() + MAX_PAIRING_ACCEPTANCE_LIFETIME,
            clock: anchor.clock(self.platform.clone()),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.platform.hook.lock().unwrap().take();
        self.controller.stop_intake();
    }
}
fn public(seed: u8) -> TlsPublicKey {
    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
    let public =
        p256::PublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    TlsPublicKey::from_spki_der(public.to_public_key_der().unwrap().as_bytes()).unwrap()
}
fn invitation() -> PairingInvitation {
    PairingInvitation::new(PairingInvitationFields {
        ceremony_nonce: PairingNonce::from_bytes([31; 32]).unwrap(),
        attestation_challenge: PairingChallenge::from_bytes([32; 32]).unwrap(),
        pc: PcIdentity::from_bytes([33; 32]).unwrap(),
        recipient_device: DeviceId::from_bytes([34; 16]).unwrap(),
        pc_signing_key: public(20),
        pc_transport_key: public(21),
        relay_address: "127.0.0.1:29991".parse().unwrap(),
        route: [35; 32],
    })
    .unwrap()
}
fn fill(bytes: &mut [u8]) -> Result<(), BridgeError> {
    bytes.fill(55);
    Ok(())
}

#[test]
fn valid_original_is_retained_with_the_actual_existing_intent_without_preparing() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let original = invitation();
    let scan = fixture.controller.begin_pairing_scan().unwrap();
    let start = scan.guard.started;
    let deadline = scan.guard.deadline;
    fixture
        .platform
        .nanos
        .fetch_add(200_000_000_000, Ordering::AcqRel); // Real camera/permission delay model.
    assert_eq!(
        scan.accept_with(original.to_qr_text(), fill),
        NativePairingScanResult::Read
    );
    {
        let accepted = scan.accepted.lock().unwrap();
        let accepted = accepted.as_ref().unwrap();
        assert_eq!(accepted.invitation, original);
        let context = &accepted.intent.state.original;
        assert_eq!(context.handle.as_bytes(), &[55; 32]);
        assert_eq!(
            context.challenge.as_bytes(),
            original.fields().attestation_challenge.as_bytes()
        );
        assert_eq!(context.ceremony_nonce, original.fields().ceremony_nonce);
        assert_eq!(context.pc, original.fields().pc);
        assert_eq!(context.recipient_device, original.fields().recipient_device);
        assert_eq!(context.pc_signing_key, original.fields().pc_signing_key);
        assert_eq!(context.pc_transport_key, original.fields().pc_transport_key);
        assert_eq!(context.invitation_context, original.context_digest());
        assert_eq!(context.started_at, start);
        assert_eq!(context.deadline, deadline);
        assert!(Arc::ptr_eq(
            &accepted.intent.state,
            &fixture
                .controller
                .creation_slot
                .lock()
                .unwrap()
                .upgrade()
                .unwrap()
        ));
    }
    assert_eq!(fixture.bytes(), before);
    assert_eq!(fixture.platform.key_calls.load(Ordering::Acquire), 0);
    assert!(!format!("{scan:?}").contains(&original.to_qr_text()));
}

#[test]
fn malformed_or_duplicate_input_is_terminal_and_never_uses_rng_early() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new();
    let before = fixture.bytes();
    for text in [
        "not a QR".to_string(),
        "x".repeat(MAX_PAIRING_INVITATION_QR_TEXT_BYTES + 1),
    ] {
        let scan = fixture.controller.begin_pairing_scan().unwrap();
        assert_eq!(
            scan.accept_with(text, |_| panic!("no RNG before valid original")),
            NativePairingScanResult::Invalid
        );
        assert!(scan.check_current().is_err());
        assert_eq!(
            scan.accept_with(invitation().to_qr_text(), |_| panic!("no retry RNG")),
            NativePairingScanResult::Unavailable
        );
        assert!(
            fixture
                .controller
                .creation_slot
                .lock()
                .unwrap()
                .upgrade()
                .is_none()
        );
        drop(scan);
    }
    let scan = fixture.controller.begin_pairing_scan().unwrap();
    let copy = Arc::clone(&scan);
    assert_eq!(
        scan.accept_with(invitation().to_qr_text(), fill),
        NativePairingScanResult::Read
    );
    assert_eq!(
        copy.accept_with(invitation().to_qr_text(), |_| panic!(
            "foreign clone shares take bit"
        )),
        NativePairingScanResult::Unavailable
    );
    assert!(scan.accepted.lock().unwrap().is_none());
    assert_eq!(fixture.bytes(), before);
    assert_eq!(fixture.platform.key_calls.load(Ordering::Acquire), 0);
}

#[test]
fn lock_owner_boot_regression_and_original_deadline_rejections_do_not_rearm() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for failure in 0..6 {
        let fixture = Fixture::new();
        let before = fixture.bytes();
        let scan = fixture.controller.begin_pairing_scan().unwrap();
        match failure {
            0 => fixture.platform.secure.store(false, Ordering::Release),
            1 => fixture.controller.stop_intake(),
            2 => fixture.platform.boot.store(2, Ordering::Release),
            3 => fixture.platform.nanos.store(999_999_999, Ordering::Release),
            4 => {
                fixture
                    .platform
                    .nanos
                    .fetch_add(300_000_000_000, Ordering::AcqRel);
            }
            _ => fixture.platform.clock_failed.store(true, Ordering::Release),
        }
        assert_eq!(
            scan.accept_with(invitation().to_qr_text(), |_| panic!(
                "ineligible scan cannot create handle"
            )),
            NativePairingScanResult::Unavailable
        );
        assert!(scan.check_current().is_err());
        assert_eq!(fixture.bytes(), before);
        assert_eq!(fixture.platform.key_calls.load(Ordering::Acquire), 0);
    }
    let fixture = Fixture::new();
    fixture.platform.secure.store(false, Ordering::Release);
    assert!(fixture.controller.begin_pairing_scan().is_err());
    assert!(!SCAN_RESERVED.load(Ordering::Acquire));
}

#[test]
fn entropy_failure_and_zero_handle_never_retry_or_generate_keys() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new();
    let before = fixture.bytes();
    for zero in [false, true] {
        let scan = fixture.controller.begin_pairing_scan().unwrap();
        let calls = AtomicUsize::new(0);
        assert_eq!(
            scan.accept_with(invitation().to_qr_text(), |bytes| {
                calls.fetch_add(1, Ordering::AcqRel);
                if zero {
                    bytes.fill(0);
                    Ok(())
                } else {
                    Err(BridgeError::NativeUnavailable)
                }
            }),
            NativePairingScanResult::Unavailable
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert!(
            fixture
                .controller
                .creation_slot
                .lock()
                .unwrap()
                .upgrade()
                .is_none()
        );
        drop(scan);
    }
    assert_eq!(fixture.bytes(), before);
    assert_eq!(fixture.platform.key_calls.load(Ordering::Acquire), 0);
}

#[test]
fn shared_creation_slot_arbitrates_concurrent_rust_only_intent_without_stealing() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let scan = fixture.controller.begin_pairing_scan().unwrap();
    assert!(matches!(
        fixture.controller.begin_pairing_scan(),
        Err(BridgeError::Busy)
    ));
    let other = fixture
        .controller
        .begin_key_creation_from_trusted_host(fixture.legacy_context())
        .unwrap();
    assert_eq!(
        scan.accept_with(invitation().to_qr_text(), fill),
        NativePairingScanResult::Unavailable
    );
    assert!(other.state.check_current().is_ok());
    assert!(Arc::ptr_eq(
        &other.state,
        &fixture
            .controller
            .creation_slot
            .lock()
            .unwrap()
            .upgrade()
            .unwrap()
    ));
    drop(other);
    drop(scan);
    let scan = fixture.controller.begin_pairing_scan().unwrap();
    assert_eq!(
        scan.accept_with(invitation().to_qr_text(), fill),
        NativePairingScanResult::Read
    );
    assert!(matches!(
        fixture
            .controller
            .begin_key_creation_from_trusted_host(fixture.legacy_context()),
        Err(BridgeError::Busy)
    ));
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn failure_after_actual_intent_creation_retires_the_slot_without_preparing() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let scan = fixture.controller.begin_pairing_scan().unwrap();
    *fixture.platform.fail_after_intent.lock().unwrap() = Some(Arc::downgrade(&fixture.controller));
    assert_eq!(
        scan.accept_with(invitation().to_qr_text(), fill),
        NativePairingScanResult::Unavailable
    );
    assert!(scan.accepted.lock().unwrap().is_none());
    assert!(
        fixture
            .controller
            .creation_slot
            .lock()
            .unwrap()
            .upgrade()
            .is_none()
    );
    assert!(scan.check_current().is_err());
    assert_eq!(fixture.bytes(), before);
    assert_eq!(fixture.platform.key_calls.load(Ordering::Acquire), 0);
}

#[test]
fn rust_only_take_retains_exact_scope_and_live_owner_cancellation() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let original = invitation();
    let scan = fixture.controller.begin_pairing_scan().unwrap();
    assert_eq!(
        scan.accept_with(original.to_qr_text(), fill),
        NativePairingScanResult::Read
    );
    let (retained, intent) = fixture.controller.take_pairing_scan(&scan).unwrap();
    assert_eq!(retained, original);
    assert!(intent.state.check_current().is_ok());
    scan.cancel();
    assert!(intent.state.check_current().is_err());
    assert!(fixture.controller.take_pairing_scan(&scan).is_err());
    drop(scan);
    assert!(SCAN_RESERVED.load(Ordering::Acquire));
    drop(intent);
    assert!(!SCAN_RESERVED.load(Ordering::Acquire));
    assert_eq!(fixture.bytes(), before);
    assert_eq!(fixture.platform.key_calls.load(Ordering::Acquire), 0);
}

#[test]
fn rust_only_taken_intent_expires_with_its_original_scan_owner_still_live() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let scan = fixture.controller.begin_pairing_scan().unwrap();
    assert_eq!(
        scan.accept_with(invitation().to_qr_text(), fill),
        NativePairingScanResult::Read
    );
    let (_, intent) = fixture.controller.take_pairing_scan(&scan).unwrap();
    assert!(intent.state.check_current().is_ok());
    fixture
        .platform
        .nanos
        .fetch_add(300_000_000_000, Ordering::AcqRel);
    assert!(intent.state.check_current().is_err());
    assert!(scan.check_current().is_err());
    assert_eq!(fixture.bytes(), before);
    assert_eq!(fixture.platform.key_calls.load(Ordering::Acquire), 0);
}

#[test]
fn last_scan_handle_drop_cancels_taken_intent_but_retains_its_slot_and_owner_lease() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let scan = fixture.controller.begin_pairing_scan().unwrap();
    assert_eq!(
        scan.accept_with(invitation().to_qr_text(), fill),
        NativePairingScanResult::Read
    );
    let (_, intent) = fixture.controller.take_pairing_scan(&scan).unwrap();
    let slot = fixture.controller.creation_slot.lock().unwrap().clone();
    let lease = Arc::downgrade(&fixture.controller._owner_lease);
    let original_owner = Arc::clone(&scan);
    drop(scan);
    assert!(intent.state.check_current().is_ok());
    drop(original_owner);
    assert!(intent.state.check_current().is_err());
    assert!(SCAN_RESERVED.load(Ordering::Acquire));
    assert!(slot.upgrade().is_some());
    assert!(matches!(
        fixture.controller.begin_pairing_scan(),
        Err(BridgeError::Busy)
    ));
    assert_eq!(fixture.bytes(), before);
    assert_eq!(fixture.platform.key_calls.load(Ordering::Acquire), 0);
    drop(fixture);
    assert!(lease.upgrade().is_some());
    assert!(matches!(OwnerLease::acquire(), Err(BridgeError::Busy)));
    drop(intent);
    assert!(slot.upgrade().is_none());
    assert!(!SCAN_RESERVED.load(Ordering::Acquire));
    assert!(lease.upgrade().is_none());
    drop(OwnerLease::acquire().unwrap());
}

#[test]
fn cancellation_does_not_wait_for_a_busy_native_callback_or_hold_input_mutexes() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let scan = fixture.controller.begin_pairing_scan().unwrap();
    let (entered, arrived) = mpsc::sync_channel(1);
    let (released, release) = mpsc::sync_channel(1);
    let callback_scan = Arc::clone(&scan);
    let controller = Arc::clone(&fixture.controller);
    *fixture.platform.hook.lock().unwrap() = Some(Box::new(move || {
        assert!(callback_scan.accepted.try_lock().is_ok());
        assert!(controller.creation_slot.try_lock().is_ok());
        assert!(matches!(
            controller.begin_pairing_scan(),
            Err(BridgeError::Busy)
        ));
        entered.send(()).unwrap();
        release.recv_timeout(Duration::from_secs(5)).unwrap();
    }));
    let worker_scan = Arc::clone(&scan);
    let worker = std::thread::spawn(move || {
        worker_scan.accept_with(invitation().to_qr_text(), |_| {
            panic!("cancelled before RNG")
        })
    });
    arrived.recv_timeout(Duration::from_secs(5)).unwrap();
    scan.cancel();
    assert!(scan.guard.cancelled.load(Ordering::Acquire));
    released.send(()).unwrap();
    assert_eq!(worker.join().unwrap(), NativePairingScanResult::Unavailable);
    assert!(scan.accepted.lock().unwrap().is_none());
    assert_eq!(fixture.bytes(), before);
    assert_eq!(fixture.platform.key_calls.load(Ordering::Acquire), 0);
}

#[test]
fn wrong_controller_and_callback_unwind_cannot_restore_an_input_scope() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new();
    let other = Fixture::with_lease(Arc::clone(&fixture.controller._owner_lease));
    let scan = fixture.controller.begin_pairing_scan().unwrap();
    assert_eq!(
        scan.accept_with(invitation().to_qr_text(), fill),
        NativePairingScanResult::Read
    );
    assert!(matches!(
        other.controller.take_pairing_scan(&scan),
        Err(BridgeError::InvalidObservation)
    ));
    assert!(scan.check_current().is_err());
    drop(scan);
    let scan = fixture.controller.begin_pairing_scan().unwrap();
    *fixture.platform.hook.lock().unwrap() =
        Some(Box::new(|| panic!("synthetic native callback unwind")));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        scan.accept_with(invitation().to_qr_text(), fill)
    }));
    assert!(result.is_err());
    assert!(scan.check_current().is_err());
}

#[test]
fn direct_check_unwind_also_revokes_an_already_taken_intent() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new();
    let before = fixture.bytes();
    let scan = fixture.controller.begin_pairing_scan().unwrap();
    assert_eq!(
        scan.accept_with(invitation().to_qr_text(), fill),
        NativePairingScanResult::Read
    );
    let (_, intent) = fixture.controller.take_pairing_scan(&scan).unwrap();
    *fixture.platform.hook.lock().unwrap() =
        Some(Box::new(|| panic!("synthetic check-current unwind")));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scan.check_current()));
    assert!(result.is_err());
    assert!(intent.state.check_current().is_err());
    assert_eq!(fixture.bytes(), before);
    assert_eq!(fixture.platform.key_calls.load(Ordering::Acquire), 0);
}

#[test]
fn weak_controller_cannot_be_revived_and_scan_retains_the_original_owner_lease() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = Fixture::new();
    let scan = fixture.controller.begin_pairing_scan().unwrap();
    drop(fixture);
    assert!(scan.check_current().is_err());
    assert!(matches!(OwnerLease::acquire(), Err(BridgeError::Busy)));
    drop(scan);
    let lease = OwnerLease::acquire().unwrap();
    drop(lease);
    assert!(!SCAN_RESERVED.load(Ordering::Acquire));
}
