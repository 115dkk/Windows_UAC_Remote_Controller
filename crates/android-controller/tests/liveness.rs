// SPDX-License-Identifier: GPL-2.0-or-later
//! Isolated host-model files and synthetic public keys only. No enrollment
//! ceremony, native TLS/signing, phone authentication or Windows action proof.
#![cfg(any(windows, target_os = "linux"))]

use android_controller::{
    DurableInbox, LocalAttestationChallenge, LocalKeyHandle, LocalKeySetDescriptor,
    PeerAssociationDescriptor, PeerAssociationMutation, PeerAssociationRef, PeerAssociationRemoval,
    PeerLeaseError,
};
use approval_protocol::{DeviceId, PcIdentity};
use notification_policy::{
    AlertMode, CapacityLimits, ClockReading, LocalTime, MonotonicTime, NotificationPolicy, Weekday,
};
use p256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};
use phone_request_core::{InboxClock, PhoneBootId};
use phone_state_store::{NativePrivateDirectory, STAGING_FILE_NAME};
use secure_channel::TlsPublicKey;

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
        ms * 1_000_000,
    )
    .unwrap()
}
fn public(seed: u8) -> TlsPublicKey {
    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
    let public =
        p256::PublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    TlsPublicKey::from_spki_der(public.to_public_key_der().unwrap().as_bytes()).unwrap()
}
fn handle(value: u8) -> LocalKeyHandle {
    LocalKeyHandle::from_bytes([value; 32]).unwrap()
}
fn challenge(value: u8) -> LocalAttestationChallenge {
    LocalAttestationChallenge::from_bytes([value + 64; 32]).unwrap()
}
fn local(value: u8, first_key: u8) -> LocalKeySetDescriptor {
    LocalKeySetDescriptor::new(
        handle(value),
        challenge(value),
        public(first_key),
        public(first_key + 1),
        public(first_key + 2),
    )
    .unwrap()
}
fn peer(revision: u64) -> PeerAssociationDescriptor {
    PeerAssociationDescriptor::new(
        PcIdentity::from_bytes([7; 32]).unwrap(),
        DeviceId::from_bytes([9; 16]).unwrap(),
        revision,
        handle(1),
        public(20),
        public(21),
    )
    .unwrap()
}
fn reference(mutation: PeerAssociationMutation) -> PeerAssociationRef {
    match mutation {
        PeerAssociationMutation::Recorded(value)
        | PeerAssociationMutation::AlreadyRecorded(value) => value,
    }
}
fn enrolled(temp: &tempfile::TempDir) -> (DurableInbox, PeerAssociationRef) {
    let (mut owner, initial) = DurableInbox::create_fresh_host_model(
        directory(temp),
        NotificationPolicy::default(),
        CapacityLimits::default(),
        boot(),
        clock(0),
    )
    .unwrap();
    assert!(initial.update().effects().is_empty());
    let _ = owner
        .begin_local_key_creation(handle(1), challenge(1))
        .unwrap();
    let _ = owner.record_local_key_creation(local(1, 3)).unwrap();
    let (_, mutation) = owner
        .record_peer_association_from_trusted_host(peer(1))
        .unwrap();
    (owner, reference(mutation))
}

#[test]
fn unchanged_association_survives_unrelated_committed_changes_and_rejected_candidates() {
    let temp = tempfile::tempdir().unwrap();
    let (mut owner, current) = enrolled(&temp);
    let lease = owner.lease_peer_association(current).unwrap();
    let copy = lease.clone();
    assert!(lease.belongs_to_owner(&owner));
    assert_eq!(lease.association().reference(), current);
    assert_eq!(lease.local_keys(), &local(1, 3));
    assert!(format!("{lease:?}").contains("[redacted]"));

    let update = owner
        .update_policy(NotificationPolicy::new(None, AlertMode::Silent), clock(1))
        .unwrap();
    assert!(update.update().effects().is_empty());
    let _ = owner.poll(clock(2)).unwrap();
    let _ = owner.clear_history().unwrap();
    let _ = owner
        .record_pending_outcomes(activity_journal::UnixMillis::new(1).unwrap())
        .unwrap();
    let _ = owner
        .begin_local_key_creation(handle(2), challenge(2))
        .unwrap();
    let _ = owner.record_local_key_creation(local(2, 7)).unwrap();
    let (_, duplicate) = owner
        .record_peer_association_from_trusted_host(peer(1))
        .unwrap();
    assert_eq!(reference(duplicate), current);
    assert!(
        owner
            .record_peer_association_from_trusted_host(peer(2))
            .is_err()
    );
    assert!(
        owner
            .begin_local_key_creation(handle(1), challenge(1))
            .is_err()
    );
    assert!(!lease.is_revoked());
    assert!(!copy.is_revoked());
}

#[test]
fn removal_revokes_all_copies_and_same_keys_reenrollment_cannot_rearm_them() {
    let temp = tempfile::tempdir().unwrap();
    let (mut owner, original) = enrolled(&temp);
    let old = owner.lease_peer_association(original).unwrap();
    let old_copy = old.clone();
    let (_, removed) = owner
        .revoke_peer_association_from_trusted_host(original)
        .unwrap();
    assert_eq!(removed, PeerAssociationRemoval::Removed);
    assert!(old.is_revoked() && old_copy.is_revoked());
    assert!(matches!(
        owner.lease_peer_association(original),
        Err(PeerLeaseError::AssociationNotCurrent)
    ));
    let (_, inserted) = owner
        .record_peer_association_from_trusted_host(peer(1))
        .unwrap();
    let current = reference(inserted);
    assert!(current.generation() > original.generation());
    let new = owner.lease_peer_association(current).unwrap();
    let (_, removal) = owner
        .revoke_peer_association_from_trusted_host(original)
        .unwrap();
    assert_eq!(removal, PeerAssociationRemoval::NotCurrent);
    assert!(!new.is_revoked());
    assert!(old.is_revoked() && old_copy.is_revoked());
}

#[test]
fn sixty_four_live_entries_are_bounded_and_only_dead_weak_entries_release_capacity() {
    let temp = tempfile::tempdir().unwrap();
    let (mut owner, original) = enrolled(&temp);
    let mut leases: Vec<_> = (0..64)
        .map(|_| owner.lease_peer_association(original).unwrap())
        .collect();
    let held_copy = leases[0].clone();
    assert!(matches!(
        owner.lease_peer_association(original),
        Err(PeerLeaseError::Capacity)
    ));
    assert!(leases.iter().all(|lease| !lease.is_revoked()));
    let _ = owner
        .revoke_peer_association_from_trusted_host(original)
        .unwrap();
    assert!(leases.iter().all(|lease| lease.is_revoked()));
    let (_, inserted) = owner
        .record_peer_association_from_trusted_host(peer(1))
        .unwrap();
    let current = reference(inserted);
    assert!(matches!(
        owner.lease_peer_association(current),
        Err(PeerLeaseError::Capacity)
    ));
    drop(leases.remove(0));
    assert!(matches!(
        owner.lease_peer_association(current),
        Err(PeerLeaseError::Capacity)
    ));
    drop(held_copy);
    let fresh = owner.lease_peer_association(current).unwrap();
    assert!(!fresh.is_revoked());
    assert!(matches!(
        owner.lease_peer_association(current),
        Err(PeerLeaseError::Capacity)
    ));
    drop(leases);
    drop(fresh);
    for _ in 0..128 {
        drop(owner.lease_peer_association(current).unwrap());
    }
}

#[test]
fn ordinary_and_peer_commit_failures_revoke_every_previously_issued_lease() {
    for peer_commit in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let (mut owner, current) = enrolled(&temp);
        let lease = owner.lease_peer_association(current).unwrap();
        let copy = lease.clone();
        // Explicit isolated filesystem fault fixture; the store must not remove
        // or overwrite this unowned staging state or publish a candidate.
        std::fs::write(
            temp.path().join(STAGING_FILE_NAME),
            b"synthetic interrupted staging",
        )
        .unwrap();
        if peer_commit {
            assert!(
                owner
                    .revoke_peer_association_from_trusted_host(current)
                    .is_err()
            );
        } else {
            assert!(owner.clear_history().is_err());
        }
        assert!(owner.fault().is_some());
        assert!(lease.is_revoked() && copy.is_revoked());
        assert!(lease.belongs_to_owner(&owner), "identity is not health");
        assert!(matches!(
            owner.lease_peer_association(current),
            Err(PeerLeaseError::Owner(_))
        ));
    }
}

#[test]
fn committed_domain_clock_fault_also_revokes_peer_only_leases() {
    let temp = tempfile::tempdir().unwrap();
    let (mut owner, current) = enrolled(&temp);
    let lease = owner.lease_peer_association(current).unwrap();
    let _ = owner.poll(clock(2)).unwrap();
    let failed = owner.poll(clock(1)).unwrap();
    assert!(failed.update().fault().is_some());
    assert!(lease.is_revoked());
    assert!(matches!(
        owner.lease_peer_association(current),
        Err(PeerLeaseError::DomainFault(_))
    ));
}

#[test]
fn owner_drop_revokes_without_poll_and_reopen_has_a_distinct_lifetime() {
    let temp = tempfile::tempdir().unwrap();
    let (mut owner, current) = enrolled(&temp);
    let lease = owner.lease_peer_association(current).unwrap();
    drop(owner);
    assert!(lease.is_revoked());
    let (mut reopened, _) =
        DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(1)).unwrap();
    assert!(!lease.belongs_to_owner(&reopened));
    let replacement = reopened.lease_peer_association(current).unwrap();
    assert!(!replacement.is_revoked());
    assert!(lease.is_revoked());
}
