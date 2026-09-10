// SPDX-License-Identifier: GPL-2.0-or-later
//! Software P-256 signatures and the real host SnapshotStore/DurableInbox.
//! These are not native Android, QR, attestation, consent or PC-commit tests.

use std::{
    collections::VecDeque,
    fs,
    sync::{Mutex, atomic::AtomicUsize},
};

use approval_protocol::DeviceId;
use notification_policy::{
    CapacityLimits, ClockReading, LocalTime, MonotonicTime, NotificationPolicy, Weekday,
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use phone_request_core::{InboxClock, PhoneBootId};
use phone_state_store::{
    INTENT_FILE_NAME, NativePrivateDirectory, SNAPSHOT_FILE_NAME, STAGING_FILE_NAME,
};
use service_protocol::{
    EnrollmentAcceptanceFields, MAX_ENROLLMENT_ACCEPTANCE_BYTES, PairingChallenge,
    UnsignedEnrollmentAcceptance,
};

use super::*;
use crate::{
    LocalAttestationChallenge, LocalKeyHandle, PeerAssociationError, PeerAssociationMutation,
};

fn public(seed: u8) -> TlsPublicKey {
    let signing = SigningKey::from_slice(&[seed; 32]).unwrap();
    let point = p256::PublicKey::from_sec1_bytes(
        signing.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .unwrap();
    TlsPublicKey::from_spki_der(point.to_public_key_der().unwrap().as_bytes()).unwrap()
}

fn local(which: u8, first_key: u8) -> LocalKeySetDescriptor {
    LocalKeySetDescriptor::new(
        LocalKeyHandle::from_bytes([which; 32]).unwrap(),
        LocalAttestationChallenge::from_bytes([which + 64; 32]).unwrap(),
        public(first_key),
        public(first_key + 1),
        public(first_key + 2),
    )
    .unwrap()
}

fn add_local(owner: &mut DurableInbox, local: &LocalKeySetDescriptor) {
    let _ = owner
        .begin_local_key_creation(local.handle(), local.challenge())
        .unwrap();
    let _ = owner.record_local_key_creation(local.clone()).unwrap();
}

fn boot() -> PhoneBootId {
    PhoneBootId::from_native_boot_count(5).unwrap()
}

fn inbox_clock(ms: u64) -> InboxClock {
    InboxClock::new(
        ClockReading::new(
            MonotonicTime::from_millis(ms),
            LocalTime::new(Weekday::Monday, 600).unwrap(),
        ),
        ms * 1_000_000,
    )
    .unwrap()
}

fn pc(value: u8) -> PcIdentity {
    PcIdentity::from_bytes([value; 32]).unwrap()
}

fn nonce(value: u8) -> PairingNonce {
    PairingNonce::from_bytes([value; 32]).unwrap()
}

fn directory(temp: &tempfile::TempDir) -> NativePrivateDirectory {
    NativePrivateDirectory::from_native_app_data(temp.path()).unwrap()
}

/// Deterministic trusted-provider model only, not Android elapsed-time QA.
/// Once only one sample remains it is retained until the test changes it.
struct ControlledClock {
    samples: Mutex<VecDeque<Result<Instant, SocketClockUnavailable>>>,
    reads: AtomicUsize,
}
impl ControlledClock {
    fn new(now: Instant) -> Self {
        Self {
            samples: Mutex::new(VecDeque::from([Ok(now)])),
            reads: AtomicUsize::new(0),
        }
    }

    fn set_samples(
        &self,
        samples: impl IntoIterator<Item = Result<Instant, SocketClockUnavailable>>,
    ) {
        *self.samples.lock().unwrap() = samples.into_iter().collect();
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::Acquire)
    }
}
impl SocketClock for ControlledClock {
    fn now(&self) -> Result<Instant, SocketClockUnavailable> {
        self.reads.fetch_add(1, Ordering::AcqRel);
        let mut samples = self.samples.lock().unwrap();
        if samples.len() > 1 {
            samples.pop_front().unwrap()
        } else {
            samples
                .front()
                .copied()
                .unwrap_or(Err(SocketClockUnavailable))
        }
    }
}

struct Fixture {
    temp: tempfile::TempDir,
    owner: DurableInbox,
    local: LocalKeySetDescriptor,
    base: Instant,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let (mut owner, _) = DurableInbox::create_fresh_host_model(
            directory(&temp),
            NotificationPolicy::default(),
            CapacityLimits::default(),
            boot(),
            inbox_clock(0),
        )
        .unwrap();
        let local = local(1, 3);
        add_local(&mut owner, &local);
        Self {
            temp,
            owner,
            local,
            base: Instant::now(),
        }
    }

    fn context(&self, value: u8) -> PairingAcceptanceContext {
        PairingAcceptanceContext {
            local_keys: self.local.clone(),
            pc: pc(1),
            pc_signing_key: public(20),
            pc_transport_key: public(21),
            ceremony_nonce: nonce(value),
            clock: Arc::new(ControlledClock::new(self.base)),
            started_at: self.base,
            deadline: self.base + MAX_PAIRING_ACCEPTANCE_LIFETIME,
        }
    }

    fn fields(&self, value: u8) -> EnrollmentAcceptanceFields {
        EnrollmentAcceptanceFields {
            ceremony_nonce: nonce(value),
            attestation_challenge: PairingChallenge::from_bytes(*self.local.challenge().as_bytes())
                .unwrap(),
            pc: pc(1),
            recipient_device: DeviceId::from_bytes([1; 16]).unwrap(),
            registry_revision: 8,
            phone_keys: PhoneKeyDigest::from_keys(
                self.local.approval_key(),
                self.local.denial_key(),
                self.local.transport_key(),
            )
            .unwrap(),
            pc_signing_key: public(20),
            pc_transport_key: public(21),
        }
    }

    fn pending(&mut self, value: u8) -> PendingPairingAcceptance {
        self.owner
            .begin_pairing_acceptance_at(self.context(value), self.base + Duration::from_secs(10))
            .unwrap()
    }

    fn snapshot(&self) -> Vec<u8> {
        fs::read(self.temp.path().join(SNAPSHOT_FILE_NAME)).unwrap()
    }

    fn assert_rejected_without_write(&self, before: &[u8]) {
        assert_eq!(self.snapshot(), before);
        assert!(self.owner.fault().is_none());
        assert!(self.owner.peer_associations().unwrap().is_empty());
        assert_eq!(self.owner.peer_associations().unwrap().next_generation(), 1);
        assert!(!self.temp.path().join(INTENT_FILE_NAME).exists());
    }
}

fn signed(fields: EnrollmentAcceptanceFields, signer_seed: u8) -> Vec<u8> {
    let statement = UnsignedEnrollmentAcceptance::new(fields).unwrap();
    let signer = SigningKey::from_slice(&[signer_seed; 32]).unwrap();
    let signature: Signature = signer.sign(&statement.signing_bytes());
    statement
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
        .to_wire()
}

#[test]
fn signed_acceptance_commits_existing_full_owner_and_survives_reopen() {
    let mut fixture = Fixture::new();
    let before = fixture.snapshot();
    let pending = fixture.pending(1);
    assert_eq!(fixture.snapshot(), before); // Capture is not a store mutation.
    assert!(
        DurableInbox::open_existing_host_model(directory(&fixture.temp), boot(), inbox_clock(1))
            .is_err()
    );

    // Unrelated durable metadata changes do not create a second writer or
    // replace the exact local tuple captured by the pending ceremony.
    let other_local = local(2, 6);
    add_local(&mut fixture.owner, &other_local);
    let keys = fixture.owner.local_keys().unwrap().clone();
    let policy = fixture.owner.policy().unwrap().clone();
    let history = fixture.owner.history().unwrap().to_vec();
    let wire = signed(fixture.fields(1), 20);
    let committed = fixture
        .owner
        .commit_pairing_acceptance_with_clock(pending, &wire, || {
            fixture.base + Duration::from_secs(20)
        })
        .unwrap();
    assert!(committed.receipt().changed());
    let reference = committed.association();
    let association = fixture
        .owner
        .peer_associations()
        .unwrap()
        .resolve(reference)
        .unwrap()
        .clone();
    let descriptor = association.descriptor();
    assert_eq!(descriptor.pc(), pc(1));
    assert_eq!(
        descriptor.recipient_device_id(),
        DeviceId::from_bytes([1; 16]).unwrap()
    );
    assert_eq!(descriptor.pc_registry_revision(), 8);
    assert_eq!(descriptor.local_key_handle(), fixture.local.handle());
    assert_eq!(descriptor.pc_signing_key(), &public(20));
    assert_eq!(descriptor.pc_transport_key(), &public(21));
    assert_eq!(fixture.owner.local_keys().unwrap(), &keys);
    assert_eq!(fixture.owner.policy().unwrap(), &policy);
    assert_eq!(fixture.owner.history().unwrap(), history);

    drop(fixture.owner);
    let (mut reopened, _) =
        DurableInbox::open_existing_host_model(directory(&fixture.temp), boot(), inbox_clock(2))
            .unwrap();
    assert_eq!(
        reopened.peer_associations().unwrap().resolve(reference),
        Some(&association)
    );
    assert_eq!(reopened.local_keys().unwrap(), &keys);
    assert_eq!(reopened.policy().unwrap(), &policy);
    assert_eq!(reopened.history().unwrap(), history);
    // A replay cannot obtain a new expectation beside a current association.
    let context = PairingAcceptanceContext {
        local_keys: fixture.local,
        pc: pc(1),
        pc_signing_key: public(20),
        pc_transport_key: public(21),
        ceremony_nonce: nonce(2),
        clock: Arc::new(ControlledClock::new(fixture.base)),
        started_at: fixture.base,
        deadline: fixture.base + MAX_PAIRING_ACCEPTANCE_LIFETIME,
    };
    assert_eq!(
        reopened
            .begin_pairing_acceptance_at(context, fixture.base + Duration::from_secs(30))
            .unwrap_err(),
        PairingAcceptanceError::AlreadyAssociated
    );
}

#[test]
fn public_path_uses_one_captured_projection_coordinate_for_all_three_clock_reads() {
    let mut fixture = Fixture::new();
    // Deliberately use a different Instant coordinate than continuing std time.
    // Only the captured provider can supply valid samples in this coordinate.
    let coordinate = fixture.base + Duration::from_secs(3_600);
    let clock = Arc::new(ControlledClock::new(coordinate + Duration::from_secs(10)));
    let mut context = fixture.context(1);
    context.started_at = coordinate;
    context.deadline = coordinate + MAX_PAIRING_ACCEPTANCE_LIFETIME;
    context.clock = clock.clone();
    let pending = fixture
        .owner
        .begin_pairing_acceptance_from_trusted_host(context)
        .unwrap();
    assert_eq!(clock.reads(), 1);
    clock.set_samples([
        Ok(coordinate + Duration::from_secs(20)),
        Ok(coordinate + Duration::from_secs(21)),
    ]);
    let wire = signed(fixture.fields(1), 20);
    let committed = fixture
        .owner
        .commit_pairing_acceptance(pending, &wire)
        .unwrap();
    assert_eq!(clock.reads(), 3);
    assert!(
        fixture
            .owner
            .peer_associations()
            .unwrap()
            .resolve(committed.association())
            .is_some()
    );
}

#[test]
fn public_path_expires_on_provider_advance_without_waiting_for_std_time() {
    for expire_after_verification in [false, true] {
        let mut fixture = Fixture::new();
        let before = fixture.snapshot();
        let clock = Arc::new(ControlledClock::new(fixture.base + Duration::from_secs(10)));
        let mut context = fixture.context(1);
        context.clock = clock.clone();
        let original_deadline = context.deadline;
        let pending = fixture
            .owner
            .begin_pairing_acceptance_from_trusted_host(context)
            .unwrap();
        let wire = signed(fixture.fields(1), 20);
        // Model suspend-inclusive native advancement without sleeping or
        // changing wall/std time. The private observation helper is NOT used.
        let expired = fixture.base + Duration::from_secs(301);
        if expire_after_verification {
            clock.set_samples([Ok(fixture.base + Duration::from_secs(20)), Ok(expired)]);
        } else {
            clock.set_samples([Ok(expired)]);
        }
        assert_eq!(
            fixture
                .owner
                .commit_pairing_acceptance(pending, &wire)
                .unwrap_err(),
            PairingAcceptanceError::Expired
        );
        assert_eq!(clock.reads(), if expire_after_verification { 3 } else { 2 });
        assert!(Instant::now() < original_deadline);
        fixture.assert_rejected_without_write(&before);
    }
}

#[test]
fn public_factory_clock_failure_creates_no_reservation_or_store_intent() {
    let mut fixture = Fixture::new();
    let before = fixture.snapshot();
    let clock = Arc::new(ControlledClock::new(fixture.base));
    clock.set_samples([Err(SocketClockUnavailable)]);
    let mut context = fixture.context(1);
    context.clock = clock.clone();
    assert_eq!(
        fixture
            .owner
            .begin_pairing_acceptance_from_trusted_host(context)
            .unwrap_err(),
        PairingAcceptanceError::ClockUnavailable
    );
    assert_eq!(clock.reads(), 1);
    fixture.assert_rejected_without_write(&before);
    clock.set_samples([Ok(fixture.base + Duration::from_secs(10))]);
    let mut fresh_context = fixture.context(2);
    fresh_context.clock = clock;
    drop(
        fixture
            .owner
            .begin_pairing_acceptance_from_trusted_host(fresh_context)
            .unwrap(),
    );
}

#[test]
fn public_receive_clock_failure_before_decode_or_precommit_consumes_attempt() {
    for fail_after_verification in [false, true] {
        let mut fixture = Fixture::new();
        let before = fixture.snapshot();
        let clock = Arc::new(ControlledClock::new(fixture.base + Duration::from_secs(10)));
        let mut context = fixture.context(1);
        context.clock = clock.clone();
        let pending = fixture
            .owner
            .begin_pairing_acceptance_from_trusted_host(context)
            .unwrap();
        let wire = if fail_after_verification {
            clock.set_samples([
                Ok(fixture.base + Duration::from_secs(20)),
                Err(SocketClockUnavailable),
            ]);
            signed(fixture.fields(1), 20)
        } else {
            clock.set_samples([Err(SocketClockUnavailable)]);
            vec![0] // Clock rejection must precede even malformed wire decoding.
        };
        assert_eq!(
            fixture
                .owner
                .commit_pairing_acceptance(pending, &wire)
                .unwrap_err(),
            PairingAcceptanceError::ClockUnavailable
        );
        assert_eq!(clock.reads(), if fail_after_verification { 3 } else { 2 });
        fixture.assert_rejected_without_write(&before);
        // The rejected attempt is gone. Only a fresh independently supplied
        // context/nonce may occupy the now-released PC/local reservation.
        clock.set_samples([Ok(fixture.base + Duration::from_secs(21))]);
        let mut next = fixture.context(2);
        next.clock = clock;
        drop(
            fixture
                .owner
                .begin_pairing_acceptance_from_trusted_host(next)
                .unwrap(),
        );
    }
}

#[test]
fn receiving_domain_clock_fault_irreversibly_retires_pending_and_rejects_new_factory() {
    let mut fixture = Fixture::new();
    let context = fixture.context(1);
    let pending = fixture
        .owner
        .begin_pairing_acceptance_from_trusted_host(context)
        .unwrap();
    let wire = signed(fixture.fields(1), 20);
    let _ = fixture.owner.poll(inbox_clock(20)).unwrap();
    assert!(!pending.reservation.cancelled.load(Ordering::Acquire));
    let _ = fixture.owner.poll(inbox_clock(19)).unwrap();
    assert_eq!(
        fixture.owner.inbox_fault().unwrap(),
        Some(InboxFault::NativeClockRegressed)
    );
    assert!(fixture.owner.fault().is_none()); // Persisted domain fault, not store failure.
    assert!(pending.reservation.cancelled.load(Ordering::Acquire));
    let before = fixture.snapshot();
    assert_eq!(
        fixture
            .owner
            .commit_pairing_acceptance(pending, &wire)
            .unwrap_err(),
        PairingAcceptanceError::DomainFault(InboxFault::NativeClockRegressed)
    );
    assert_eq!(fixture.snapshot(), before);
    assert!(fixture.owner.peer_associations().unwrap().is_empty());
    assert_eq!(
        fixture
            .owner
            .begin_pairing_acceptance_from_trusted_host(fixture.context(2))
            .unwrap_err(),
        PairingAcceptanceError::DomainFault(InboxFault::NativeClockRegressed)
    );
    // A later forward observation is not domain recovery and cannot recreate
    // trust authority or the cancelled original expectation.
    let _ = fixture.owner.poll(inbox_clock(21)).unwrap();
    assert_eq!(
        fixture
            .owner
            .begin_pairing_acceptance_from_trusted_host(fixture.context(3))
            .unwrap_err(),
        PairingAcceptanceError::DomainFault(InboxFault::NativeClockRegressed)
    );
    assert!(fixture.owner.peer_associations().unwrap().is_empty());
}

#[test]
fn normal_history_and_policy_commits_preserve_original_pairing_context() {
    let mut fixture = Fixture::new();
    let clock = Arc::new(ControlledClock::new(fixture.base + Duration::from_secs(10)));
    let mut context = fixture.context(1);
    context.clock = clock.clone();
    let pending = fixture
        .owner
        .begin_pairing_acceptance_from_trusted_host(context)
        .unwrap();
    let _ = fixture.owner.clear_history().unwrap();
    let _ = fixture
        .owner
        .update_policy(NotificationPolicy::default(), inbox_clock(20))
        .unwrap();
    assert_eq!(fixture.owner.inbox_fault().unwrap(), None);
    assert!(!pending.reservation.cancelled.load(Ordering::Acquire));
    clock.set_samples([Ok(fixture.base + Duration::from_secs(20))]);
    let wire = signed(fixture.fields(1), 20);
    let committed = fixture
        .owner
        .commit_pairing_acceptance(pending, &wire)
        .unwrap();
    assert!(
        fixture
            .owner
            .peer_associations()
            .unwrap()
            .resolve(committed.association())
            .is_some()
    );
}

#[test]
fn genuine_signatures_cannot_change_original_nonce_challenge_keys_pc_or_transport_pin() {
    let rewrites: [fn(&mut EnrollmentAcceptanceFields); 5] = [
        |fields| fields.ceremony_nonce = nonce(99),
        |fields| fields.attestation_challenge = PairingChallenge::from_bytes([99; 32]).unwrap(),
        |fields| fields.phone_keys = PhoneKeyDigest::from_bytes([99; 32]),
        |fields| fields.pc = pc(99),
        |fields| fields.pc_transport_key = public(99),
    ];
    for rewrite in rewrites {
        let mut fixture = Fixture::new();
        let before = fixture.snapshot();
        let pending = fixture.pending(1);
        let mut fields = fixture.fields(1);
        rewrite(&mut fields);
        let wire = signed(fields, 20);
        let error = fixture
            .owner
            .commit_pairing_acceptance_with_clock(pending, &wire, || {
                fixture.base + Duration::from_secs(20)
            })
            .unwrap_err();
        assert_eq!(error, PairingAcceptanceError::BindingMismatch);
        fixture.assert_rejected_without_write(&before);
    }
}

#[test]
fn same_pc_may_use_its_same_original_pin_for_both_pc_roles() {
    let mut fixture = Fixture::new();
    let mut context = fixture.context(1);
    context.pc_transport_key = public(20);
    let pending = fixture
        .owner
        .begin_pairing_acceptance_at(context, fixture.base)
        .unwrap();
    let mut fields = fixture.fields(1);
    fields.pc_transport_key = public(20);
    let wire = signed(fields, 20);
    let committed = fixture
        .owner
        .commit_pairing_acceptance_with_clock(pending, &wire, || {
            fixture.base + Duration::from_secs(20)
        })
        .unwrap();
    let association = fixture
        .owner
        .peer_associations()
        .unwrap()
        .resolve(committed.association())
        .unwrap();
    assert_eq!(association.descriptor().pc_signing_key(), &public(20));
    assert_eq!(association.descriptor().pc_transport_key(), &public(20));
}

#[test]
fn independent_pc_pin_and_real_signature_verification_are_mandatory() {
    for change_claimed_pin in [false, true] {
        let mut fixture = Fixture::new();
        let before = fixture.snapshot();
        let pending = fixture.pending(1);
        let mut fields = fixture.fields(1);
        if change_claimed_pin {
            fields.pc_signing_key = public(99);
        }
        let wire = signed(fields, 99);
        let error = fixture
            .owner
            .commit_pairing_acceptance_with_clock(pending, &wire, || {
                fixture.base + Duration::from_secs(20)
            })
            .unwrap_err();
        assert_eq!(
            error,
            PairingAcceptanceError::Protocol(if change_claimed_pin {
                PairingError::UntrustedPcKey
            } else {
                PairingError::InvalidSignature
            })
        );
        fixture.assert_rejected_without_write(&before);
    }
}

#[test]
fn all_incorrect_phone_role_orders_reject_even_with_a_valid_pc_signature() {
    for order in [[0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        let mut fixture = Fixture::new();
        let before = fixture.snapshot();
        let pending = fixture.pending(1);
        let mut fields = fixture.fields(1);
        let keys = [
            fixture.local.approval_key(),
            fixture.local.denial_key(),
            fixture.local.transport_key(),
        ];
        fields.phone_keys =
            PhoneKeyDigest::from_keys(keys[order[0]], keys[order[1]], keys[order[2]]).unwrap();
        let wire = signed(fields, 20);
        assert_eq!(
            fixture
                .owner
                .commit_pairing_acceptance_with_clock(pending, &wire, || fixture.base
                    + Duration::from_secs(20),)
                .unwrap_err(),
            PairingAcceptanceError::BindingMismatch
        );
        fixture.assert_rejected_without_write(&before);
    }
}

#[test]
fn tampered_signature_malformed_and_oversized_wire_never_reach_intent() {
    let mut fixture = Fixture::new();
    let before = fixture.snapshot();
    for (index, kind) in (0u8..).zip(0..6) {
        let value = index + 1;
        let pending = fixture.pending(value);
        let mut wire = signed(fixture.fields(value), 20);
        match kind {
            0 => *wire.last_mut().unwrap() ^= 1,
            1 => {
                wire.pop();
            }
            2 => wire.resize(MAX_ENROLLMENT_ACCEPTANCE_BYTES + 1, 0),
            3 => wire[10] = 99,
            4 => wire.extend_from_slice(&[0]),
            5 => wire[124..132].fill(0), // Authenticated nonzero revision is mandatory.
            _ => unreachable!(),
        }
        assert!(matches!(
            fixture
                .owner
                .commit_pairing_acceptance_with_clock(pending, &wire, || fixture.base
                    + Duration::from_secs(20),),
            Err(PairingAcceptanceError::Protocol(_))
        ));
        fixture.assert_rejected_without_write(&before);
    }
}

#[test]
fn factory_rejects_absent_preparing_or_different_full_local_tuple() {
    let mut fixture = Fixture::new();
    let missing = local(2, 6);
    let mut context = fixture.context(1);
    context.local_keys = missing.clone();
    let before = fixture.snapshot();
    assert_eq!(
        fixture
            .owner
            .begin_pairing_acceptance_at(context, fixture.base)
            .unwrap_err(),
        PairingAcceptanceError::LocalKeysChanged
    );
    fixture.assert_rejected_without_write(&before);

    let _ = fixture
        .owner
        .begin_local_key_creation(missing.handle(), missing.challenge())
        .unwrap();
    let before = fixture.snapshot();
    let mut context = fixture.context(2);
    context.local_keys = missing;
    assert_eq!(
        fixture
            .owner
            .begin_pairing_acceptance_at(context, fixture.base)
            .unwrap_err(),
        PairingAcceptanceError::LocalKeysChanged
    );

    for changed in [
        LocalKeySetDescriptor::new(
            fixture.local.handle(),
            fixture.local.challenge(),
            public(6),
            public(7),
            public(8),
        )
        .unwrap(),
        LocalKeySetDescriptor::new(
            fixture.local.handle(),
            LocalAttestationChallenge::from_bytes([99; 32]).unwrap(),
            public(3),
            public(4),
            public(5),
        )
        .unwrap(),
        LocalKeySetDescriptor::new(
            fixture.local.handle(),
            fixture.local.challenge(),
            public(4),
            public(3),
            public(5),
        )
        .unwrap(),
    ] {
        let mut context = fixture.context(3);
        context.local_keys = changed;
        assert_eq!(
            fixture
                .owner
                .begin_pairing_acceptance_at(context, fixture.base)
                .unwrap_err(),
            PairingAcceptanceError::LocalKeysChanged
        );
    }
    fixture.assert_rejected_without_write(&before);
}

#[test]
fn factory_checks_both_pc_pins_against_every_committed_local_role() {
    let mut fixture = Fixture::new();
    let other = local(2, 6);
    add_local(&mut fixture.owner, &other);
    let before = fixture.snapshot();
    for colliding in [3, 4, 5, 6, 7, 8] {
        for signing in [false, true] {
            let mut context = fixture.context(colliding);
            if signing {
                context.pc_signing_key = public(colliding);
            } else {
                context.pc_transport_key = public(colliding);
            }
            assert_eq!(
                fixture
                    .owner
                    .begin_pairing_acceptance_at(context, fixture.base)
                    .unwrap_err(),
                PairingAcceptanceError::PcPinConflict
            );
            fixture.assert_rejected_without_write(&before);
        }
    }
}

#[test]
fn factory_rejects_existing_pc_handle_and_cross_pc_pin_conflicts() {
    let mut fixture = Fixture::new();
    let other = local(2, 6);
    add_local(&mut fixture.owner, &other);
    let descriptor = PeerAssociationDescriptor::new(
        pc(2),
        DeviceId::from_bytes([2; 16]).unwrap(),
        4,
        other.handle(),
        public(30),
        public(31),
    )
    .unwrap();
    let _ = fixture
        .owner
        .record_peer_association_from_trusted_host(descriptor)
        .unwrap();
    let before = fixture.snapshot();
    for kind in 0..4 {
        let mut context = fixture.context(1);
        match kind {
            0 => context.pc = pc(2),
            1 => context.local_keys = other.clone(),
            2 => context.pc_signing_key = public(31),
            3 => context.pc_transport_key = public(30),
            _ => unreachable!(),
        }
        let expected = if kind < 2 {
            PairingAcceptanceError::AlreadyAssociated
        } else {
            PairingAcceptanceError::PcPinConflict
        };
        assert_eq!(
            fixture
                .owner
                .begin_pairing_acceptance_at(context, fixture.base)
                .unwrap_err(),
            expected
        );
        assert_eq!(fixture.snapshot(), before);
        assert!(fixture.owner.fault().is_none());
        assert_eq!(fixture.owner.peer_associations().unwrap().len(), 1);
    }
}

#[test]
fn valid_signed_device_assignment_still_passes_existing_composite_relationship_checks() {
    let mut fixture = Fixture::new();
    let other = local(2, 6);
    add_local(&mut fixture.owner, &other);
    let descriptor = PeerAssociationDescriptor::new(
        pc(2),
        DeviceId::from_bytes([1; 16]).unwrap(),
        4,
        other.handle(),
        public(30),
        public(31),
    )
    .unwrap();
    let _ = fixture
        .owner
        .record_peer_association_from_trusted_host(descriptor)
        .unwrap();
    let before = fixture.snapshot();
    let pending = fixture.pending(1);
    let wire = signed(fixture.fields(1), 20);
    assert_eq!(
        fixture
            .owner
            .commit_pairing_acceptance_with_clock(pending, &wire, || fixture.base
                + Duration::from_secs(20))
            .unwrap_err(),
        PairingAcceptanceError::Association(PeerAssociationMutationError::Rejected(
            PeerAssociationError::DeviceAlreadyAssociated
        ))
    );
    assert_eq!(fixture.snapshot(), before);
    assert_eq!(fixture.owner.peer_associations().unwrap().len(), 1);
    assert_eq!(
        fixture.owner.peer_associations().unwrap().next_generation(),
        2
    );
    assert!(fixture.owner.fault().is_none());
    assert!(!fixture.temp.path().join(INTENT_FILE_NAME).exists());
}

#[test]
fn original_lifetime_is_never_rebased_and_clock_rollback_rejects() {
    let mut fixture = Fixture::new();
    let before = fixture.snapshot();
    for deadline in [
        fixture.base,
        fixture.base - Duration::from_secs(1),
        fixture.base + Duration::from_secs(301),
    ] {
        let mut context = fixture.context(1);
        context.deadline = deadline;
        assert_eq!(
            fixture
                .owner
                .begin_pairing_acceptance_at(context, fixture.base)
                .unwrap_err(),
            PairingAcceptanceError::InvalidLifetime
        );
    }
    assert_eq!(
        fixture
            .owner
            .begin_pairing_acceptance_at(fixture.context(2), fixture.base - Duration::from_secs(1))
            .unwrap_err(),
        PairingAcceptanceError::ClockRollback
    );
    assert_eq!(
        fixture
            .owner
            .begin_pairing_acceptance_at(
                fixture.context(3),
                fixture.base + Duration::from_secs(300)
            )
            .unwrap_err(),
        PairingAcceptanceError::Expired
    );
    fixture.assert_rejected_without_write(&before);

    let cases = [
        ([9, 9], PairingAcceptanceError::ClockRollback),
        ([20, 19], PairingAcceptanceError::ClockRollback),
        ([300, 300], PairingAcceptanceError::Expired),
        ([299, 300], PairingAcceptanceError::Expired),
    ];
    for (index, (samples, expected)) in (10u8..).zip(cases) {
        let pending = fixture.pending(index);
        let wire = signed(fixture.fields(index), 20);
        let mut samples = samples.into_iter();
        let error = fixture
            .owner
            .commit_pairing_acceptance_with_clock(pending, &wire, || {
                fixture.base + Duration::from_secs(samples.next().unwrap())
            })
            .unwrap_err();
        assert_eq!(error, expected);
        fixture.assert_rejected_without_write(&before);
    }
}

#[test]
fn repeated_contexts_cancelled_handles_and_drop_obey_one_live_reservation() {
    let mut fixture = Fixture::new();
    let other = local(2, 6);
    add_local(&mut fixture.owner, &other);
    let before = fixture.snapshot();
    let first = fixture.pending(1);
    for kind in 0..4 {
        let mut context = fixture.context(2);
        match kind {
            0 => {}                                  // Both PC and handle match.
            1 => context.local_keys = other.clone(), // PC match.
            2 => context.pc = pc(2),                 // Handle match.
            3 => {
                context.pc = pc(2);
                context.local_keys = other.clone();
                context.ceremony_nonce = nonce(1);
            }
            _ => unreachable!(),
        }
        assert_eq!(
            fixture
                .owner
                .begin_pairing_acceptance_at(context, fixture.base + Duration::from_secs(11))
                .unwrap_err(),
            PairingAcceptanceError::AlreadyPending
        );
    }
    first.cancel();
    assert_eq!(
        fixture
            .owner
            .begin_pairing_acceptance_at(fixture.context(3), fixture.base + Duration::from_secs(11))
            .unwrap_err(),
        PairingAcceptanceError::AlreadyPending
    );
    let old_wire = signed(fixture.fields(1), 20);
    assert_eq!(
        fixture
            .owner
            .commit_pairing_acceptance_with_clock(first, &old_wire, || fixture.base
                + Duration::from_secs(20))
            .unwrap_err(),
        PairingAcceptanceError::Cancelled
    );
    fixture.assert_rejected_without_write(&before);

    let second = fixture.pending(4);
    drop(second); // No aliases, checkpoints or remote rows are removed.
    let fresh = fixture.pending(5);
    assert_eq!(
        fixture
            .owner
            .commit_pairing_acceptance_with_clock(fresh, &old_wire, || fixture.base
                + Duration::from_secs(20))
            .unwrap_err(),
        PairingAcceptanceError::BindingMismatch
    );
    drop(fixture.pending(6));
    fixture.assert_rejected_without_write(&before);
}

#[test]
fn same_saved_bytes_in_a_reopened_owner_cannot_consume_old_context() {
    let mut fixture = Fixture::new();
    let pending = fixture.pending(1);
    let wire = signed(fixture.fields(1), 20);
    drop(fixture.owner);
    let (mut reopened, _) =
        DurableInbox::open_existing_host_model(directory(&fixture.temp), boot(), inbox_clock(1))
            .unwrap();
    let before = fs::read(fixture.temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    assert_eq!(
        reopened
            .commit_pairing_acceptance_with_clock(pending, &wire, || fixture.base
                + Duration::from_secs(20))
            .unwrap_err(),
        PairingAcceptanceError::DifferentOwner
    );
    assert_eq!(
        fs::read(fixture.temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        before
    );
    assert!(reopened.peer_associations().unwrap().is_empty());
    assert!(reopened.fault().is_none());
}

#[test]
fn later_association_and_removal_cannot_resurrect_pending_ceremony() {
    let mut fixture = Fixture::new();
    let pending = fixture.pending(1);
    let descriptor = PeerAssociationDescriptor::new(
        pc(1),
        DeviceId::from_bytes([1; 16]).unwrap(),
        9,
        fixture.local.handle(),
        public(20),
        public(21),
    )
    .unwrap();
    let (_, mutation) = fixture
        .owner
        .record_peer_association_from_trusted_host(descriptor)
        .unwrap();
    let reference = match mutation {
        PeerAssociationMutation::Recorded(reference) => reference,
        PeerAssociationMutation::AlreadyRecorded(_) => panic!("fresh synthetic association"),
    };
    let _ = fixture
        .owner
        .revoke_peer_association_from_trusted_host(reference)
        .unwrap();
    let before = fixture.snapshot();
    let wire = signed(fixture.fields(1), 20);
    assert_eq!(
        fixture
            .owner
            .commit_pairing_acceptance_with_clock(pending, &wire, || fixture.base
                + Duration::from_secs(20))
            .unwrap_err(),
        PairingAcceptanceError::Cancelled
    );
    assert_eq!(fixture.snapshot(), before);
    assert!(fixture.owner.peer_associations().unwrap().is_empty());
    assert_eq!(
        fixture.owner.peer_associations().unwrap().next_generation(),
        2
    );
    assert!(fixture.owner.fault().is_none());
}

#[test]
fn signed_acceptance_replay_after_removal_fails_new_original_nonce() {
    let mut fixture = Fixture::new();
    let first = fixture.pending(1);
    let wire = signed(fixture.fields(1), 20);
    let committed = fixture
        .owner
        .commit_pairing_acceptance_with_clock(first, &wire, || {
            fixture.base + Duration::from_secs(20)
        })
        .unwrap();
    let _ = fixture
        .owner
        .revoke_peer_association_from_trusted_host(committed.association())
        .unwrap();
    let before = fixture.snapshot();
    let next = fixture.pending(2);
    assert_eq!(
        fixture
            .owner
            .commit_pairing_acceptance_with_clock(next, &wire, || fixture.base
                + Duration::from_secs(20))
            .unwrap_err(),
        PairingAcceptanceError::BindingMismatch
    );
    assert_eq!(fixture.snapshot(), before);
    assert_eq!(
        fixture.owner.peer_associations().unwrap().next_generation(),
        2
    );
}

#[test]
fn failed_real_store_commit_latches_owner_and_never_returns_association() {
    for blocker in [INTENT_FILE_NAME, STAGING_FILE_NAME] {
        let mut fixture = Fixture::new();
        let pending = fixture.pending(1);
        let wire = signed(fixture.fields(1), 20);
        fs::write(
            fixture.temp.path().join(blocker),
            b"synthetic blocked pairing transaction",
        )
        .unwrap();
        assert!(matches!(
            fixture
                .owner
                .commit_pairing_acceptance_with_clock(pending, &wire, || fixture.base
                    + Duration::from_secs(20)),
            Err(PairingAcceptanceError::Association(
                PeerAssociationMutationError::Owner(_)
            ))
        ));
        assert!(fixture.owner.fault().is_some());
        assert!(fixture.owner.peer_associations().is_err());
        assert!(fixture.owner.local_keys().is_err());
        assert!(fixture.owner.policy().is_err());
        assert!(fixture.owner.history().is_err());
        assert!(
            fixture
                .owner
                .begin_pairing_acceptance_at(
                    fixture.context(2),
                    fixture.base + Duration::from_secs(20)
                )
                .is_err()
        );
        // No reset, delete, fallback-open or rollback assertion is made. A
        // real uncertain write may have persisted a different set of bytes.
    }
}

#[test]
fn real_owner_holds_at_most_32_distinct_live_contexts_and_drop_releases_slot() {
    let mut fixture = Fixture::new();
    // The existing local ledger has the same 32-set bound. Populate each via
    // Preparing -> CreatedUnverified commits, not a validator returning true.
    for value in 2..=32 {
        add_local(&mut fixture.owner, &local(value, value * 3));
    }
    let before = fixture.snapshot();
    let mut contexts = Vec::new();
    for value in 1..=32 {
        let mut context = fixture.context(value);
        context.local_keys = local(value, value * 3);
        context.pc = pc(value);
        context.pc_signing_key = public(200);
        context.pc_transport_key = public(201);
        contexts.push(
            fixture
                .owner
                .begin_pairing_acceptance_at(context, fixture.base)
                .unwrap(),
        );
    }
    assert_eq!(contexts.len(), MAX_PENDING_PAIRING_ACCEPTANCES);
    // All 32 committed handles are reserved; a duplicate never creates a 33rd.
    let mut duplicate = fixture.context(100);
    duplicate.pc_signing_key = public(200);
    duplicate.pc_transport_key = public(201);
    assert_eq!(
        fixture
            .owner
            .begin_pairing_acceptance_at(duplicate, fixture.base)
            .unwrap_err(),
        PairingAcceptanceError::AlreadyPending
    );
    drop(contexts.remove(0));
    let mut replacement = fixture.context(101);
    replacement.pc_signing_key = public(200);
    replacement.pc_transport_key = public(201);
    let replacement = fixture
        .owner
        .begin_pairing_acceptance_at(replacement, fixture.base)
        .unwrap();
    drop(replacement);
    assert_eq!(fixture.snapshot(), before);
    assert!(fixture.owner.peer_associations().unwrap().is_empty());
}

#[test]
fn independent_pending_contexts_survive_an_unrelated_successful_association() {
    let mut fixture = Fixture::new();
    let other = local(2, 6);
    add_local(&mut fixture.owner, &other);
    let first = fixture.pending(1);
    let mut context = fixture.context(2);
    context.local_keys = other.clone();
    context.pc = pc(2);
    context.pc_signing_key = public(30);
    context.pc_transport_key = public(31);
    let second = fixture
        .owner
        .begin_pairing_acceptance_at(context, fixture.base)
        .unwrap();
    let first_wire = signed(fixture.fields(1), 20);
    let first = fixture
        .owner
        .commit_pairing_acceptance_with_clock(first, &first_wire, || {
            fixture.base + Duration::from_secs(20)
        })
        .unwrap();
    let mut fields = fixture.fields(2);
    fields.attestation_challenge =
        PairingChallenge::from_bytes(*other.challenge().as_bytes()).unwrap();
    fields.pc = pc(2);
    fields.recipient_device = DeviceId::from_bytes([2; 16]).unwrap();
    fields.phone_keys = PhoneKeyDigest::from_keys(
        other.approval_key(),
        other.denial_key(),
        other.transport_key(),
    )
    .unwrap();
    fields.pc_signing_key = public(30);
    fields.pc_transport_key = public(31);
    let second_wire = signed(fields, 30);
    let second = fixture
        .owner
        .commit_pairing_acceptance_with_clock(second, &second_wire, || {
            fixture.base + Duration::from_secs(21)
        })
        .unwrap();
    assert_eq!(fixture.owner.peer_associations().unwrap().len(), 2);
    assert!(
        fixture
            .owner
            .peer_associations()
            .unwrap()
            .resolve(first.association())
            .is_some()
    );
    assert!(
        fixture
            .owner
            .peer_associations()
            .unwrap()
            .resolve(second.association())
            .is_some()
    );
}

#[test]
fn receiving_boundary_rechecks_full_key_tuple_not_only_handle() {
    let mut fixture = Fixture::new();
    let mut pending = fixture.pending(1);
    let wire = signed(fixture.fields(1), 20);
    let before = fixture.snapshot();
    // Public ledger mutation cannot replace a CreatedUnverified tuple. This
    // private unit-only adversarial stale snapshot checks that future mutation
    // paths cannot reduce the receive check to handle-only equality. No native
    // key operation or production way to forge Pending is being modeled.
    pending.reservation = Arc::new(PairingReservation {
        local_keys: LocalKeySetDescriptor::new(
            fixture.local.handle(),
            fixture.local.challenge(),
            public(4),
            public(3),
            public(5),
        )
        .unwrap(),
        pc: pc(1),
        pc_signing_key: public(20),
        pc_transport_key: public(21),
        ceremony_nonce: nonce(1),
        cancelled: AtomicBool::new(false),
    });
    assert_eq!(
        fixture
            .owner
            .commit_pairing_acceptance_with_clock(pending, &wire, || fixture.base
                + Duration::from_secs(20))
            .unwrap_err(),
        PairingAcceptanceError::LocalKeysChanged
    );
    fixture.assert_rejected_without_write(&before);
}
