// SPDX-License-Identifier: GPL-2.0-or-later
//! Public typed-checkpoint tests using synthetic keys only. No protected file,
//! real enrollment, Android authentication or Windows action is exercised here.

#![forbid(unsafe_code)]

use std::{
    cell::Cell,
    time::{Duration, Instant},
};

use approval_core::{
    ApprovalEngine, DecisionError, DeviceKeys, EnrollmentError, MAX_TRUSTED_DEVICES,
    PrivilegedDeviceRegistry, RegistryCheckpoint, RegistryCheckpointEntry, RegistryCheckpointError,
    RequestTtl,
};
use approval_protocol::{
    DecisionPublicKey, DecisionPurpose, DeviceId, OsSession, PcIdentity, RequestBinding,
    RequestContent, SignedDecision, UnsignedDecision,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

fn device(value: u8) -> DeviceId {
    DeviceId::from_bytes([value; 16]).unwrap()
}

fn public_key(seed: u8, compressed: bool) -> DecisionPublicKey {
    let synthetic = SigningKey::from_slice(&[seed; 32]).unwrap();
    DecisionPublicKey::from_sec1_bytes(
        synthetic
            .verifying_key()
            .to_encoded_point(compressed)
            .as_bytes(),
    )
    .unwrap()
}

fn keys(seed: u8) -> DeviceKeys {
    DeviceKeys::new(public_key(seed * 2, true), public_key(seed * 2 + 1, true)).unwrap()
}

fn revision(checkpoint: &RegistryCheckpoint, id: DeviceId) -> u64 {
    checkpoint
        .entries()
        .iter()
        .find(|entry| entry.device_id() == id)
        .unwrap()
        .revision()
}

fn entry(id: u8, revision: u64, key_seed: u8) -> RegistryCheckpointEntry {
    RegistryCheckpointEntry::new(device(id), revision, keys(key_seed)).unwrap()
}

#[test]
fn restore_preserves_capacity_revision_gaps_and_explicit_reenrollment_sequence() {
    let mut registry = PrivilegedDeviceRegistry::initialize_for_privileged_host(4).unwrap();
    registry
        .enroll_from_privileged_host(device(1), keys(1))
        .unwrap();
    registry
        .enroll_from_privileged_host(device(2), keys(2))
        .unwrap();
    registry
        .replace_from_privileged_host(device(1), keys(3))
        .unwrap();
    registry.revoke_from_privileged_host(device(2)).unwrap();

    let checkpoint = registry.checkpoint_for_privileged_host();
    assert_eq!(checkpoint.capacity(), 4);
    assert_eq!(checkpoint.next_revision(), 4);
    assert_eq!(checkpoint.entries().len(), 1);
    assert_eq!(revision(&checkpoint, device(1)), 3);
    assert_eq!(checkpoint.entries()[0].keys(), &keys(3));

    let mut restored =
        PrivilegedDeviceRegistry::restore_for_privileged_host(checkpoint.clone()).unwrap();
    assert_eq!(restored.checkpoint_for_privileged_host(), checkpoint);
    assert_eq!(restored.device_count(), 1);
    // Revoked membership stays absent until an explicit privileged action. No
    // permanent ID/key ban is invented; original semantics allow re-enrollment.
    restored
        .enroll_from_privileged_host(device(2), keys(2))
        .unwrap();
    let reenrolled = restored.checkpoint_for_privileged_host();
    assert_eq!(revision(&reenrolled, device(1)), 3);
    assert_eq!(revision(&reenrolled, device(2)), 4);
    assert_eq!(reenrolled.next_revision(), 5);
    assert_eq!(checkpoint.next_revision(), 4);
}

#[test]
fn empty_revoked_registry_retains_highwater_and_allows_same_id_and_keys_explicitly() {
    let mut registry = PrivilegedDeviceRegistry::initialize_for_privileged_host(1).unwrap();
    registry
        .enroll_from_privileged_host(device(1), keys(1))
        .unwrap();
    registry
        .replace_from_privileged_host(device(1), keys(1))
        .unwrap();
    registry.revoke_from_privileged_host(device(1)).unwrap();
    let checkpoint = registry.checkpoint_for_privileged_host();
    assert!(checkpoint.entries().is_empty());
    assert_eq!(checkpoint.next_revision(), 3);

    let mut restored = PrivilegedDeviceRegistry::restore_for_privileged_host(checkpoint).unwrap();
    assert_eq!(restored.device_count(), 0);
    restored
        .enroll_from_privileged_host(device(1), keys(1))
        .unwrap();
    let reenrolled = restored.checkpoint_for_privileged_host();
    assert_eq!(revision(&reenrolled, device(1)), 3);
    assert_eq!(reenrolled.next_revision(), 4);
    assert_eq!(
        restored.enroll_from_privileged_host(device(2), keys(2)),
        Err(EnrollmentError::CapacityReached)
    );
    assert_eq!(restored.checkpoint_for_privileged_host(), reenrolled);
}

#[test]
fn restored_last_allocator_value_exhausts_without_wrapping_or_changing_failed_state() {
    let checkpoint = RegistryCheckpoint::new(2, u64::MAX - 1, []).unwrap();
    let mut registry = PrivilegedDeviceRegistry::restore_for_privileged_host(checkpoint).unwrap();
    registry
        .enroll_from_privileged_host(device(1), keys(1))
        .unwrap();
    let exhausted = registry.checkpoint_for_privileged_host();
    assert_eq!(exhausted.next_revision(), u64::MAX);
    assert_eq!(revision(&exhausted, device(1)), u64::MAX - 1);
    let mut restored =
        PrivilegedDeviceRegistry::restore_for_privileged_host(exhausted.clone()).unwrap();
    assert_eq!(
        restored.enroll_from_privileged_host(device(2), keys(2)),
        Err(EnrollmentError::RevisionExhausted)
    );
    assert_eq!(restored.checkpoint_for_privileged_host(), exhausted);
    assert_eq!(
        restored.replace_from_privileged_host(device(1), keys(1)),
        Err(EnrollmentError::RevisionExhausted)
    );
    assert_eq!(restored.checkpoint_for_privileged_host(), exhausted);
    // Revocation remains available even when no new revision can be assigned.
    restored.revoke_from_privileged_host(device(1)).unwrap();
    let empty = restored.checkpoint_for_privileged_host();
    assert!(empty.entries().is_empty());
    assert_eq!(empty.next_revision(), u64::MAX);
    let mut reopened =
        PrivilegedDeviceRegistry::restore_for_privileged_host(empty.clone()).unwrap();
    assert_eq!(
        reopened.enroll_from_privileged_host(device(1), keys(1)),
        Err(EnrollmentError::RevisionExhausted)
    );
    assert_eq!(reopened.checkpoint_for_privileged_host(), empty);
}

#[test]
fn typed_checkpoint_rejects_invalid_capacity_next_revision_and_entry_revisions() {
    for capacity in [0, MAX_TRUSTED_DEVICES + 1, usize::MAX] {
        assert_eq!(
            RegistryCheckpoint::new(capacity, 1, []),
            Err(RegistryCheckpointError::InvalidCapacity)
        );
    }
    assert_eq!(
        RegistryCheckpoint::new(1, 0, []),
        Err(RegistryCheckpointError::InvalidNextRevision)
    );
    assert_eq!(
        RegistryCheckpointEntry::new(device(1), 0, keys(1)),
        Err(RegistryCheckpointError::InvalidRevision)
    );
    for (next_revision, row_revision) in [(1, 1), (1, 2), (u64::MAX, u64::MAX)] {
        assert_eq!(
            RegistryCheckpoint::new(1, next_revision, [entry(1, row_revision, 1)]),
            Err(RegistryCheckpointError::InvalidRevision)
        );
    }
    assert!(RegistryCheckpoint::new(1, 1, []).is_ok());
    assert!(RegistryCheckpoint::new(1, u64::MAX, []).is_ok());
}

#[test]
fn checkpoint_accepts_all_32_active_entries_and_canonicalizes_only_their_order() {
    assert_eq!(MAX_TRUSTED_DEVICES, 32);
    let entries: Vec<_> = (1..=32_u8)
        .rev()
        .map(|id| entry(id, u64::from(id) * 2, id))
        .collect();
    let checkpoint = RegistryCheckpoint::new(32, 100, entries).unwrap();
    assert_eq!(checkpoint.entries().len(), 32);
    assert_eq!(checkpoint.capacity(), 32);
    assert_eq!(checkpoint.next_revision(), 100);
    for (offset, row) in checkpoint.entries().iter().enumerate() {
        let id = offset as u8 + 1;
        assert_eq!(row.device_id(), device(id));
        assert_eq!(row.revision(), u64::from(id) * 2);
        assert_eq!(row.keys(), &keys(id));
    }
    let restored =
        PrivilegedDeviceRegistry::restore_for_privileged_host(checkpoint.clone()).unwrap();
    assert_eq!(restored.checkpoint_for_privileged_host(), checkpoint);
}

#[test]
fn excess_typed_input_is_rejected_after_at_most_capacity_plus_one_entries() {
    let observed = Cell::new(0);
    let entries = (1..=4_u8).map(|id| {
        observed.set(observed.get() + 1);
        entry(id, u64::from(id), id)
    });
    assert_eq!(
        RegistryCheckpoint::new(2, 10, entries),
        Err(RegistryCheckpointError::TooManyEntries)
    );
    assert_eq!(observed.get(), 3);
}

#[test]
fn duplicate_devices_and_revisions_are_rejected_without_overwriting_rows() {
    assert_eq!(
        RegistryCheckpoint::new(2, 3, [entry(1, 1, 1), entry(1, 2, 2)]),
        Err(RegistryCheckpointError::DuplicateDevice)
    );
    assert_eq!(
        RegistryCheckpoint::new(2, 3, [entry(1, 1, 1), entry(2, 1, 2)]),
        Err(RegistryCheckpointError::DuplicateRevision)
    );
}

#[test]
fn every_active_cross_purpose_key_reuse_is_rejected_after_canonical_key_parsing() {
    let first = entry(1, 1, 1); // approval seed2; denial seed3, compressed input.
    for (approval_seed, denial_seed) in [(2, 4), (4, 2), (3, 4), (4, 3)] {
        // Alternate SEC1 encoding must not disguise the same public point.
        let shared = DeviceKeys::new(
            public_key(approval_seed, false),
            public_key(denial_seed, false),
        )
        .unwrap();
        let second = RegistryCheckpointEntry::new(device(2), 2, shared).unwrap();
        assert_eq!(
            RegistryCheckpoint::new(2, 3, [first.clone(), second]),
            Err(RegistryCheckpointError::KeyReuse)
        );
    }
    // Within-device distinctness is already guaranteed by the reused typed API.
    assert_eq!(
        DeviceKeys::new(public_key(2, true), public_key(2, false)),
        Err(EnrollmentError::KeyReuse)
    );
}

#[test]
fn restored_registry_keeps_live_key_uniqueness_and_does_not_ban_revoked_key_material() {
    let checkpoint = RegistryCheckpoint::new(2, 50, [entry(1, 7, 1)]).unwrap();
    let mut registry =
        PrivilegedDeviceRegistry::restore_for_privileged_host(checkpoint.clone()).unwrap();
    assert_eq!(
        registry.enroll_from_privileged_host(device(2), keys(1)),
        Err(EnrollmentError::KeyReuse)
    );
    assert_eq!(registry.checkpoint_for_privileged_host(), checkpoint);
    registry.revoke_from_privileged_host(device(1)).unwrap();
    // Existing semantics permit an explicit trusted enrollment under another ID
    // after the old membership is revoked; no historical ban is synthesized.
    registry
        .enroll_from_privileged_host(device(2), keys(1))
        .unwrap();
    let changed = registry.checkpoint_for_privileged_host();
    assert_eq!(changed.entries().len(), 1);
    assert_eq!(revision(&changed, device(2)), 50);
    assert_eq!(changed.next_revision(), 51);
}

fn sign(binding: RequestBinding, purpose: DecisionPurpose) -> SignedDecision {
    let seed = match purpose {
        DecisionPurpose::Approve => 2,
        DecisionPurpose::Deny => 3,
    };
    let synthetic = SigningKey::from_slice(&[seed; 32]).unwrap();
    let statement = UnsignedDecision::new(binding, device(1), purpose);
    let signature: Signature = synthetic.sign(&statement.signing_bytes());
    SignedDecision::from_der(statement, signature.to_der().as_bytes()).unwrap()
}

fn open(engine: &mut ApprovalEngine, now: Instant) -> RequestBinding {
    engine
        .open_from_privileged_host(
            OsSession::new(1, 3),
            RequestContent::new(
                "Synthetic registry app",
                "C:\\Synthetic\\registry.exe",
                "synthetic pending body",
            )
            .unwrap(),
            RequestTtl::from_millis(5_000).unwrap(),
            now,
        )
        .unwrap()
        .binding()
}

#[test]
fn readonly_engine_checkpoint_and_fresh_engine_restore_never_revive_old_pending_decisions() {
    let now = Instant::now();
    let pc = PcIdentity::from_bytes([42; 32]).unwrap();
    let registry = PrivilegedDeviceRegistry::restore_for_privileged_host(
        RegistryCheckpoint::new(1, 20, [entry(1, 7, 1)]).unwrap(),
    )
    .unwrap();
    let mut original =
        ApprovalEngine::initialize_for_privileged_host(pc, registry, 2, now).unwrap();
    let binding = open(&mut original, now);
    let old_decision = sign(binding, DecisionPurpose::Approve);
    let before = original.registry_checkpoint_for_privileged_host();
    assert_eq!(original.pending_count(), 1);
    assert_eq!(revision(&before, device(1)), 7);
    assert_eq!(before.next_revision(), 20);

    original
        .revoke_device_from_privileged_host(device(1))
        .unwrap();
    original
        .enroll_device_from_privileged_host(device(1), keys(1))
        .unwrap();
    let current = original.registry_checkpoint_for_privileged_host();
    assert_eq!(revision(&current, device(1)), 20);
    assert_eq!(current.next_revision(), 21);
    assert_eq!(revision(&before, device(1)), 7);
    assert_eq!(
        original
            .submit_decision(&old_decision, now + Duration::from_millis(1))
            .unwrap_err(),
        DecisionError::EnrollmentChanged
    );
    assert_eq!(original.pending_count(), 1);
    drop(original);

    let restored_registry =
        PrivilegedDeviceRegistry::restore_for_privileged_host(current.clone()).unwrap();
    let mut restarted = ApprovalEngine::initialize_for_privileged_host(
        pc,
        restored_registry,
        2,
        now + Duration::from_millis(2),
    )
    .unwrap();
    assert_eq!(restarted.registry_checkpoint_for_privileged_host(), current);
    assert_eq!(restarted.pending_count(), 0);
    assert_ne!(restarted.boot_epoch(), binding.epoch());
    assert_eq!(
        restarted
            .submit_decision(&old_decision, now + Duration::from_millis(3))
            .unwrap_err(),
        DecisionError::WrongEpoch
    );
    let fresh_binding = open(&mut restarted, now + Duration::from_millis(4));
    let permission = restarted
        .submit_decision(
            &sign(fresh_binding, DecisionPurpose::Deny),
            now + Duration::from_millis(5),
        )
        .unwrap();
    assert_eq!(permission.binding(), fresh_binding);
    assert_eq!(permission.purpose(), DecisionPurpose::Deny);
    // Dropping a pure adapter permission performs no real Windows action.
    drop(permission);
}

#[test]
fn checkpoint_debug_exposes_no_device_identifiers_or_public_key_bytes() {
    let checkpoint = RegistryCheckpoint::new(1, 9, [entry(1, 3, 1)]).unwrap();
    let text = format!("{checkpoint:?} {:?}", checkpoint.entries()[0]);
    assert!(!text.contains(&format!("{:?}", device(1).as_bytes())));
    assert!(!text.contains(&format!("{:?}", keys(1).approval().compressed_sec1_bytes())));
    assert!(!text.contains(&format!("{:?}", keys(1).denial().compressed_sec1_bytes())));
}
