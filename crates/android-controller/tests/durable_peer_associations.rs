// SPDX-License-Identifier: GPL-2.0-or-later
//! Real host files with explicitly synthetic public keys/PC events only.
//! No Android, pairing ceremony, native auth, relay or Windows behavior is claimed.
#![cfg(any(windows, target_os = "linux"))]

use activity_journal::{OutcomeHistory, OutcomeHistoryLimits, UnixMillis};
use android_controller::{
    ControllerCheckpoint, ControllerCheckpointError, DurableFault, DurableInbox,
    LocalAttestationChallenge, LocalKeyHandle, LocalKeyLedger, LocalKeyMutationError,
    LocalKeySetDescriptor, PeerAssociationDescriptor, PeerAssociationError, PeerAssociationLedger,
    PeerAssociationMutation, PeerAssociationMutationError, PeerAssociationRef,
    PeerAssociationRemoval,
};
use approval_protocol::{
    BootEpoch, ChallengeNonce, DeviceId, ExpiryTick, OsSession, PcIdentity, RequestBinding,
    RequestContent, RequestId,
};
use notification_policy::{
    AlertMode, CapacityLimits, ClockReading, Effect, LocalTime, MonotonicTime, NotificationPolicy,
    Schedule, Weekday,
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use phone_request_core::{InboxClock, PhoneBootId, PhoneInbox, request_key};
use phone_state_store::{
    INTENT_FILE_NAME, NativePrivateDirectory, SNAPSHOT_FILE_NAME, STAGING_FILE_NAME, SnapshotStore,
};
use secure_channel::TlsPublicKey;
use service_protocol::{
    ClockCorrelation, ClockProbe, PcEvent, PcPublicKey, RequestResolution, ServiceTick,
    UnsignedPcEvent, VerifiedPcEvent,
};
use std::{cell::Cell, fs, sync::Arc};

const MILLI: u64 = 1_000_000;
fn directory(temp: &tempfile::TempDir) -> NativePrivateDirectory {
    NativePrivateDirectory::from_native_app_data(temp.path()).unwrap()
}
fn boot() -> PhoneBootId {
    PhoneBootId::from_native_boot_count(5).unwrap()
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
fn pc(value: u8) -> PcIdentity {
    PcIdentity::from_bytes([value; 32]).unwrap()
}
fn handle(value: u8) -> LocalKeyHandle {
    LocalKeyHandle::from_bytes([value; 32]).unwrap()
}
fn challenge(value: u8) -> LocalAttestationChallenge {
    LocalAttestationChallenge::from_bytes([value; 32]).unwrap()
}
fn public(seed: u8) -> TlsPublicKey {
    let signing = SigningKey::from_slice(&[seed; 32]).unwrap();
    let public = p256::PublicKey::from_sec1_bytes(
        signing.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .unwrap();
    TlsPublicKey::from_spki_der(public.to_public_key_der().unwrap().as_bytes()).unwrap()
}
fn local(which: u8, first_key: u8) -> LocalKeySetDescriptor {
    LocalKeySetDescriptor::new(
        handle(which),
        challenge(which + 64),
        public(first_key),
        public(first_key + 1),
        public(first_key + 2),
    )
    .unwrap()
}
fn peer(which: u8, local: u8, revision: u64, first_key: u8) -> PeerAssociationDescriptor {
    PeerAssociationDescriptor::new(
        pc(which),
        DeviceId::from_bytes([which; 16]).unwrap(),
        revision,
        handle(local),
        public(first_key),
        public(first_key + 1),
    )
    .unwrap()
}
fn reference(mutation: PeerAssociationMutation) -> PeerAssociationRef {
    match mutation {
        PeerAssociationMutation::Recorded(reference)
        | PeerAssociationMutation::AlreadyRecorded(reference) => reference,
    }
}
fn fresh(temp: &tempfile::TempDir) -> DurableInbox {
    DurableInbox::create_fresh_host_model(
        directory(temp),
        NotificationPolicy::default(),
        CapacityLimits::default(),
        boot(),
        clock(0),
    )
    .unwrap()
    .0
}
fn add_local(owner: &mut DurableInbox, which: u8, first_key: u8) {
    let _ = owner
        .begin_local_key_creation(handle(which), challenge(which + 64))
        .unwrap();
    let _ = owner
        .record_local_key_creation(local(which, first_key))
        .unwrap();
}
fn local_ledger() -> LocalKeyLedger {
    let mut keys = LocalKeyLedger::default();
    keys.begin_creation(handle(1), challenge(65)).unwrap();
    keys.record_created(local(1, 3)).unwrap();
    keys
}
fn associations(keys: &LocalKeyLedger) -> PeerAssociationLedger {
    let mut peers = PeerAssociationLedger::new();
    peers
        .record_from_trusted_host(peer(1, 1, 1, 20), keys)
        .unwrap();
    peers
}
fn empty_inbox() -> Vec<u8> {
    PhoneInbox::with_phone_boot(
        NotificationPolicy::default(),
        CapacityLimits::default(),
        boot(),
    )
    .checkpoint()
    .unwrap()
    .to_bytes()
    .unwrap()
}
fn empty_history() -> Vec<u8> {
    OutcomeHistory::new(OutcomeHistoryLimits::default())
        .to_bytes()
        .unwrap()
}
fn payload(temp: &tempfile::TempDir) -> Vec<u8> {
    SnapshotStore::open_existing(directory(temp))
        .unwrap()
        .snapshot()
        .unwrap()
        .to_vec()
}
fn envelope(inbox: &[u8], history: &[u8], keys: Option<&[u8]>, peers: Option<&[u8]>) -> Vec<u8> {
    let version: u16 = match (keys, peers) {
        (None, None) => 1,
        (Some(_), None) => 2,
        (Some(_), Some(_)) => 3,
        _ => panic!("invalid synthetic envelope"),
    };
    let mut bytes = b"UACOWNR\0".to_vec();
    bytes.extend_from_slice(&version.to_be_bytes());
    for part in [Some(inbox), Some(history), keys, peers]
        .into_iter()
        .flatten()
    {
        bytes.extend_from_slice(&u32::try_from(part.len()).unwrap().to_be_bytes());
    }
    for part in [Some(inbox), Some(history), keys, peers]
        .into_iter()
        .flatten()
    {
        bytes.extend_from_slice(part);
    }
    bytes
}

#[test]
fn explicit_v1_v2_migration_adds_only_absent_association_metadata() {
    let inbox = empty_inbox();
    let history = empty_history();
    let keys = local_ledger();
    let key_bytes = keys.to_bytes().unwrap();
    for (version, bytes) in [
        (1, envelope(&inbox, &history, None, None)),
        (2, envelope(&inbox, &history, Some(&key_bytes), None)),
    ] {
        let checkpoint = ControllerCheckpoint::from_bytes(&bytes).unwrap();
        assert!(checkpoint.peer_associations().is_empty());
        assert_eq!(checkpoint.peer_associations().next_generation(), 1);
        assert_eq!(checkpoint.inbox().to_bytes().unwrap(), inbox);
        assert_eq!(checkpoint.history().to_bytes().unwrap(), history);
        if version == 1 {
            assert!(checkpoint.local_keys().is_empty());
        } else {
            assert_eq!(checkpoint.local_keys(), &keys);
        }
        let migrated = checkpoint.to_bytes().unwrap();
        assert_eq!(&migrated[8..10], &3u16.to_be_bytes());
        assert!(migrated.len() >= 26);
        let reread = ControllerCheckpoint::from_bytes(&migrated).unwrap();
        assert_eq!(reread.peer_associations(), checkpoint.peer_associations());
        assert_eq!(reread.local_keys(), checkpoint.local_keys());
    }
}

#[test]
fn v2_migration_preflight_is_store_locked_and_can_reject_without_intent_or_rewrite() {
    let temp = tempfile::tempdir().unwrap();
    let keys = local_ledger();
    let old = envelope(
        &empty_inbox(),
        &empty_history(),
        Some(&keys.to_bytes().unwrap()),
        None,
    );
    drop(SnapshotStore::create_fresh(directory(&temp), &old).unwrap());
    let before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let called = Cell::new(false);
    let error = DurableInbox::open_existing_host_model_with_key_preflight(
        directory(&temp),
        boot(),
        clock(1),
        |checkpoint| {
            called.set(true);
            assert_eq!(checkpoint.local_keys(), &keys);
            assert!(checkpoint.peer_associations().is_empty());
            assert!(SnapshotStore::open_existing(directory(&temp)).is_err());
            Err(DurableFault::NativeLocalKeysUnavailable)
        },
    )
    .unwrap_err();
    assert!(called.get());
    assert_eq!(error.cause(), DurableFault::NativeLocalKeysUnavailable);
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        before
    );
    assert!(!temp.path().join(INTENT_FILE_NAME).exists());
    let (owner, _) = DurableInbox::open_existing_host_model_with_key_preflight(
        directory(&temp),
        boot(),
        clock(1),
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(owner.local_keys().unwrap(), &keys);
    assert_eq!(owner.peer_associations().unwrap().next_generation(), 1);
    drop(owner);
    assert_eq!(&payload(&temp)[8..10], &3u16.to_be_bytes());
}

#[test]
fn v3_rejects_missing_preparing_and_globally_colliding_local_key_relationships() {
    let keys = local_ledger();
    let peers = associations(&keys).to_bytes().unwrap();
    let inbox = empty_inbox();
    let history = empty_history();
    let mut preparing = LocalKeyLedger::default();
    preparing.begin_creation(handle(1), challenge(65)).unwrap();
    for invalid_keys in [LocalKeyLedger::default(), preparing] {
        let bytes = envelope(
            &inbox,
            &history,
            Some(&invalid_keys.to_bytes().unwrap()),
            Some(&peers),
        );
        assert_eq!(
            ControllerCheckpoint::from_bytes(&bytes).unwrap_err(),
            ControllerCheckpointError::PeerAssociations(PeerAssociationError::LocalKeyUnavailable)
        );
    }
    let mut colliding = keys.clone();
    colliding.begin_creation(handle(2), challenge(66)).unwrap();
    colliding.record_created(local(2, 20)).unwrap(); // An unreferenced local set collides with PC pins.
    let bytes = envelope(
        &inbox,
        &history,
        Some(&colliding.to_bytes().unwrap()),
        Some(&peers),
    );
    assert_eq!(
        ControllerCheckpoint::from_bytes(&bytes).unwrap_err(),
        ControllerCheckpointError::PeerAssociations(PeerAssociationError::PcKeyMatchesLocalKey)
    );

    let valid = envelope(
        &inbox,
        &history,
        Some(&keys.to_bytes().unwrap()),
        Some(&peers),
    );
    for end in 0..valid.len() {
        assert!(ControllerCheckpoint::from_bytes(&valid[..end]).is_err());
    }
    let mut unknown = valid.clone();
    unknown[8..10].copy_from_slice(&9u16.to_be_bytes());
    assert_eq!(
        ControllerCheckpoint::from_bytes(&unknown).unwrap_err(),
        ControllerCheckpointError::UnsupportedVersion
    );
    let mut missing_component = valid.clone();
    missing_component[22..26].fill(0);
    assert_eq!(
        ControllerCheckpoint::from_bytes(&missing_component).unwrap_err(),
        ControllerCheckpointError::InvalidEncoding
    );
    let mut trailing = valid;
    trailing.push(0);
    assert_eq!(
        ControllerCheckpoint::from_bytes(&trailing).unwrap_err(),
        ControllerCheckpointError::InvalidEncoding
    );
}

#[test]
fn durable_record_reopen_revoke_and_stale_removal_preserve_generation_highwater() {
    let temp = tempfile::tempdir().unwrap();
    let mut owner = fresh(&temp);
    add_local(&mut owner, 1, 3);
    let descriptor = peer(1, 1, 1, 20);
    let (receipt, first) = owner
        .record_peer_association_from_trusted_host(descriptor.clone())
        .unwrap();
    assert!(receipt.changed());
    let first = reference(first);
    let (repeat_receipt, repeat) = owner
        .record_peer_association_from_trusted_host(descriptor.clone())
        .unwrap();
    assert_eq!(repeat, PeerAssociationMutation::AlreadyRecorded(first));
    assert!(!repeat_receipt.changed());
    let highwater = owner.peer_associations().unwrap().next_generation();
    drop(owner);
    let (mut owner, _) =
        DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(1)).unwrap();
    assert!(owner.peer_associations().unwrap().resolve(first).is_some());
    let _ = owner.clear_history().unwrap();
    let (_, removed) = owner
        .revoke_peer_association_from_trusted_host(first)
        .unwrap();
    assert_eq!(removed, PeerAssociationRemoval::Removed);
    assert!(owner.peer_associations().unwrap().is_empty());
    assert_eq!(
        owner.peer_associations().unwrap().next_generation(),
        highwater
    );
    drop(owner);
    let (mut owner, _) =
        DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(2)).unwrap();
    assert_eq!(
        owner.peer_associations().unwrap().next_generation(),
        highwater
    );
    let (_, second) = owner
        .record_peer_association_from_trusted_host(descriptor)
        .unwrap();
    let second = reference(second);
    assert!(second.generation() > first.generation());
    let (receipt, stale) = owner
        .revoke_peer_association_from_trusted_host(first)
        .unwrap();
    assert_eq!(stale, PeerAssociationRemoval::NotCurrent);
    assert!(!receipt.changed());
    assert_eq!(
        owner
            .peer_associations()
            .unwrap()
            .lookup_current(pc(1))
            .unwrap()
            .reference(),
        second
    );
    assert!(owner.peer_associations().unwrap().resolve(first).is_none());
}

#[test]
fn invalid_association_and_local_key_collision_do_not_reserve_intent() {
    let temp = tempfile::tempdir().unwrap();
    let mut owner = fresh(&temp);
    let mut before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let descriptor = peer(1, 1, 1, 20);
    assert_eq!(
        owner
            .record_peer_association_from_trusted_host(descriptor.clone())
            .unwrap_err(),
        PeerAssociationMutationError::Rejected(PeerAssociationError::LocalKeyUnavailable)
    );
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        before
    );
    assert!(!temp.path().join(INTENT_FILE_NAME).exists());
    let _ = owner
        .begin_local_key_creation(handle(1), challenge(65))
        .unwrap();
    before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    assert_eq!(
        owner
            .record_peer_association_from_trusted_host(descriptor.clone())
            .unwrap_err(),
        PeerAssociationMutationError::Rejected(PeerAssociationError::LocalKeyUnavailable)
    );
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        before
    );
    assert!(!temp.path().join(INTENT_FILE_NAME).exists());
    let _ = owner.record_local_key_creation(local(1, 3)).unwrap();
    let (_, recorded) = owner
        .record_peer_association_from_trusted_host(descriptor)
        .unwrap();
    let recorded = reference(recorded);
    before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    assert_eq!(
        owner
            .record_peer_association_from_trusted_host(peer(1, 1, 2, 20))
            .unwrap_err(),
        PeerAssociationMutationError::Rejected(PeerAssociationError::ConflictRequiresRemoval)
    );
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        before
    );
    assert!(!temp.path().join(INTENT_FILE_NAME).exists());
    let _ = owner
        .begin_local_key_creation(handle(2), challenge(66))
        .unwrap();
    before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    assert_eq!(
        owner.record_local_key_creation(local(2, 20)).unwrap_err(),
        LocalKeyMutationError::RejectedAssociation(PeerAssociationError::PcKeyMatchesLocalKey)
    );
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        before
    );
    assert!(!temp.path().join(INTENT_FILE_NAME).exists());
    assert!(
        owner
            .local_keys()
            .unwrap()
            .get(handle(2))
            .unwrap()
            .descriptor()
            .is_none()
    );
    assert!(
        owner
            .peer_associations()
            .unwrap()
            .resolve(recorded)
            .is_some()
    );
    assert!(owner.fault().is_none());
}

#[test]
fn failed_intent_or_staging_never_returns_new_association_or_healthy_lookup() {
    for blocker in [INTENT_FILE_NAME, STAGING_FILE_NAME] {
        let temp = tempfile::tempdir().unwrap();
        let mut owner = fresh(&temp);
        add_local(&mut owner, 1, 3);
        add_local(&mut owner, 2, 6);
        let _ = owner
            .record_peer_association_from_trusted_host(peer(1, 1, 1, 20))
            .unwrap();
        let before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
        fs::write(
            temp.path().join(blocker),
            b"synthetic blocked registry transition",
        )
        .unwrap();
        let error = owner
            .record_peer_association_from_trusted_host(peer(2, 2, 1, 22))
            .unwrap_err();
        assert!(matches!(error, PeerAssociationMutationError::Owner(_)));
        assert!(owner.peer_associations().is_err());
        assert!(owner.policy().is_err());
        assert!(owner.history().is_err());
        assert!(owner.fault().is_some());
        // Only this forced early blocker proves unchanged bytes; no claim about
        // rollback after an arbitrary failed/uncertain device write.
        assert_eq!(
            fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
            before
        );
    }
}

#[test]
fn corrupt_association_keeps_full_open_intent_order_but_policy_preflight_writes_nothing() {
    let keys = local_ledger();
    let mut peers = associations(&keys).to_bytes().unwrap();
    peers[8..10].copy_from_slice(&99u16.to_be_bytes());
    let bytes = envelope(
        &empty_inbox(),
        &empty_history(),
        Some(&keys.to_bytes().unwrap()),
        Some(&peers),
    );
    let full = tempfile::tempdir().unwrap();
    drop(SnapshotStore::create_fresh(directory(&full), &bytes).unwrap());
    let error =
        DurableInbox::open_existing_host_model(directory(&full), boot(), clock(1)).unwrap_err();
    assert!(matches!(
        error.cause(),
        DurableFault::Composite(ControllerCheckpointError::PeerAssociations(_))
    ));
    assert!(full.path().join(INTENT_FILE_NAME).exists());

    let policy_only = tempfile::tempdir().unwrap();
    drop(SnapshotStore::create_fresh(directory(&policy_only), &bytes).unwrap());
    let before = fs::read(policy_only.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let called = Cell::new(false);
    let error = DurableInbox::open_existing_host_model_with_key_preflight(
        directory(&policy_only),
        boot(),
        clock(1),
        |_| {
            called.set(true);
            Ok(())
        },
    )
    .unwrap_err();
    assert!(matches!(
        error.cause(),
        DurableFault::Composite(ControllerCheckpointError::PeerAssociations(_))
    ));
    assert!(!called.get());
    assert!(!policy_only.path().join(INTENT_FILE_NAME).exists());
    assert_eq!(
        fs::read(policy_only.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        before
    );
}

fn verified(event: PcEvent) -> VerifiedPcEvent {
    let signing = SigningKey::from_slice(&[20; 32]).unwrap();
    let public =
        PcPublicKey::from_sec1_bytes(signing.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    let unsigned = UnsignedPcEvent::new(event).unwrap();
    let signature: Signature = signing.sign(&unsigned.signing_bytes());
    unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
        .verify(pc(1), &public)
        .unwrap()
}
fn correlation() -> ClockCorrelation {
    let probe = ClockProbe::start(pc(1), 0).unwrap();
    let event = verified(PcEvent::Clock {
        pc: pc(1),
        epoch: BootEpoch::from_bytes([12; 32]).unwrap(),
        probe: probe.nonce(),
        sampled_at: ServiceTick::from_nanos_since_epoch(0),
    });
    probe.complete(&event, 0).unwrap()
}
fn opened(id: u8) -> VerifiedPcEvent {
    let content = Arc::new(
        RequestContent::new(
            "Synthetic association app",
            "C:\\Synthetic\\association.exe",
            "SYNTHETIC_NOT_A_REAL_COMMAND",
        )
        .unwrap(),
    );
    let binding = RequestBinding::new(
        pc(1),
        BootEpoch::from_bytes([12; 32]).unwrap(),
        OsSession::new(1, 2),
        RequestId::from_bytes([id; 32]).unwrap(),
        ChallengeNonce::from_bytes([13; 32]).unwrap(),
        content.digest(),
        ExpiryTick::from_nanos_since_epoch(1_000 * MILLI).unwrap(),
    );
    verified(PcEvent::Opened {
        binding,
        issued_at: ServiceTick::from_nanos_since_epoch(0),
        content,
    })
}

#[test]
fn every_existing_transition_family_and_recovery_preserves_peer_ledger() {
    let temp = tempfile::tempdir().unwrap();
    let mut owner = fresh(&temp);
    add_local(&mut owner, 1, 3);
    let _ = owner
        .record_peer_association_from_trusted_host(peer(1, 1, 1, 20))
        .unwrap();
    let expected = owner.peer_associations().unwrap().clone();
    let mut source = correlation();
    let event = opened(40);
    let PcEvent::Opened {
        binding, issued_at, ..
    } = event.event()
    else {
        panic!("synthetic opened event")
    };
    let _ = owner.observe_service_clock(&source, clock(0)).unwrap();
    assert_eq!(owner.peer_associations().unwrap(), &expected);
    let _ = owner.receive_opened(&event, &mut source, clock(0)).unwrap();
    assert_eq!(owner.peer_associations().unwrap(), &expected);
    let checked = owner
        .check_pending(request_key(*binding), clock(1))
        .unwrap();
    assert!(checked.check().request().is_some());
    assert_eq!(owner.peer_associations().unwrap(), &expected);
    let _ = owner.poll(clock(2)).unwrap();
    let resolved = verified(PcEvent::Resolved {
        binding: *binding,
        issued_at: *issued_at,
        outcome: RequestResolution::Cancelled,
    });
    let _ = owner.resolve_pc(&resolved, &mut source, clock(3)).unwrap();
    assert_eq!(owner.peer_associations().unwrap(), &expected);
    let delivery = owner.pending_outcomes().unwrap()[0].delivery_id();
    let _ = owner
        .record_pending_outcomes(UnixMillis::new(10).unwrap())
        .unwrap();
    let _ = owner.acknowledge_outcome(delivery).unwrap(); // Already recorded: not delivery proof.
    let _ = owner.clear_history().unwrap();
    assert_eq!(owner.peer_associations().unwrap(), &expected);
    let _ = owner
        .update_policy(
            NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent),
            clock(4),
        )
        .unwrap();
    add_local(&mut owner, 2, 6);
    assert_eq!(owner.peer_associations().unwrap(), &expected);
    drop(owner);
    let (owner, _) =
        DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(5)).unwrap();
    assert_eq!(owner.peer_associations().unwrap(), &expected);
    drop(owner);
    assert_eq!(
        ControllerCheckpoint::from_bytes(&payload(&temp))
            .unwrap()
            .peer_associations(),
        &expected
    );

    let active = tempfile::tempdir().unwrap();
    let mut owner = fresh(&active);
    add_local(&mut owner, 1, 3);
    let _ = owner
        .record_peer_association_from_trusted_host(peer(1, 1, 1, 20))
        .unwrap();
    let expected = owner.peer_associations().unwrap().clone();
    let _ = owner
        .receive_opened(&opened(41), &mut correlation(), clock(0))
        .unwrap();
    drop(owner);
    let (owner, update) =
        DurableInbox::open_existing_host_model(directory(&active), boot(), clock(100)).unwrap();
    assert_eq!(owner.peer_associations().unwrap(), &expected);
    assert_eq!(owner.counts().unwrap().recovering(), 1);
    assert!(
        update
            .update()
            .effects()
            .iter()
            .all(|effect| !matches!(effect, Effect::Show(_) | Effect::Restore(_)))
    );
}
