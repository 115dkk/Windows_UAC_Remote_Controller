// SPDX-License-Identifier: GPL-2.0-or-later
//! Host files and synthetic public material only, not Android Keystore proof.
#![cfg(any(windows, target_os = "linux"))]
use android_controller::{
    ControllerCheckpoint, DurableFault, DurableInbox, LocalAttestationChallenge, LocalKeyHandle,
    LocalKeyLedger, LocalKeyMutationError, LocalKeyObservation, LocalKeySetDescriptor,
};
use notification_policy::{
    AlertMode, CapacityLimits, ClockReading, LocalTime, MonotonicTime, NotificationPolicy,
    Schedule, Weekday,
};
use p256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};
use phone_request_core::{InboxClock, PhoneBootId, PhoneInbox};
use phone_state_store::{
    INTENT_FILE_NAME, NativePrivateDirectory, SNAPSHOT_FILE_NAME, STAGING_FILE_NAME, SnapshotStore,
};
use secure_channel::TlsPublicKey;
use std::{cell::Cell, fs};

fn directory(temp: &tempfile::TempDir) -> NativePrivateDirectory {
    NativePrivateDirectory::from_native_app_data(temp.path()).unwrap()
}
fn boot() -> PhoneBootId {
    PhoneBootId::from_native_boot_count(2).unwrap()
}
fn clock(millis: u64) -> InboxClock {
    InboxClock::new(
        ClockReading::new(
            MonotonicTime::from_millis(millis),
            LocalTime::new(Weekday::Monday, 10).unwrap(),
        ),
        millis * 1_000_000,
    )
    .unwrap()
}
fn handle() -> LocalKeyHandle {
    LocalKeyHandle::from_bytes([1; 32]).unwrap()
}
fn challenge() -> LocalAttestationChallenge {
    LocalAttestationChallenge::from_bytes([2; 32]).unwrap()
}
fn key(seed: u8) -> TlsPublicKey {
    let signing = SigningKey::from_slice(&[seed; 32]).unwrap();
    let public = p256::PublicKey::from_sec1_bytes(
        signing.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .unwrap();
    TlsPublicKey::from_spki_der(public.to_public_key_der().unwrap().as_bytes()).unwrap()
}
fn descriptor() -> LocalKeySetDescriptor {
    LocalKeySetDescriptor::new(handle(), challenge(), key(3), key(4), key(5)).unwrap()
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
fn payload(temp: &tempfile::TempDir) -> Vec<u8> {
    SnapshotStore::open_existing(directory(temp))
        .unwrap()
        .snapshot()
        .unwrap()
        .to_vec()
}

#[test]
fn preparing_survives_restart_and_cannot_be_retried_as_a_new_creation() {
    let temp = tempfile::tempdir().unwrap();
    let mut owner = fresh(&temp);
    let receipt = owner
        .begin_local_key_creation(handle(), challenge())
        .unwrap();
    assert!(receipt.changed());
    drop(owner);
    let before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let result = DurableInbox::open_existing_host_model_with_key_preflight(
        directory(&temp),
        boot(),
        clock(1),
        |checkpoint| {
            assert!(
                checkpoint
                    .local_keys()
                    .get(handle())
                    .unwrap()
                    .descriptor()
                    .is_none()
            );
            Err(DurableFault::LocalKeyReconciliationRequired)
        },
    );
    assert_eq!(
        result.unwrap_err().cause(),
        DurableFault::LocalKeyReconciliationRequired
    );
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        before
    );
    assert!(!temp.path().join(INTENT_FILE_NAME).exists());
    let (mut owner, _) =
        DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(1)).unwrap();
    assert!(matches!(
        owner.begin_local_key_creation(handle(), challenge()),
        Err(LocalKeyMutationError::Rejected(_))
    ));
    assert!(owner.policy().is_ok());
}

#[test]
fn created_public_metadata_reopens_and_survives_policy_and_history_changes() {
    let temp = tempfile::tempdir().unwrap();
    let mut owner = fresh(&temp);
    let prepared = owner
        .begin_local_key_creation(handle(), challenge())
        .unwrap();
    assert!(prepared.changed());
    let (_, result) = owner.record_local_key_creation(descriptor()).unwrap();
    assert_eq!(result, LocalKeyObservation::RecordedUnverified);
    let expected = owner.local_keys().unwrap().clone();
    let updated = owner
        .update_policy(
            NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent),
            clock(1),
        )
        .unwrap();
    assert!(updated.receipt().changed());
    assert!(updated.update().effects().is_empty());
    let cleared = owner.clear_history().unwrap();
    assert_eq!(cleared.affected(), 0);
    drop(owner);
    let observed = Cell::new(false);
    let (mut owner, _) = DurableInbox::open_existing_host_model_with_key_preflight(
        directory(&temp),
        boot(),
        clock(2),
        |checkpoint| {
            observed.set(true);
            assert_eq!(checkpoint.local_keys(), &expected);
            // A competing store cannot acquire the same writer lock during preflight.
            assert!(SnapshotStore::open_existing(directory(&temp)).is_err());
            Ok(())
        },
    )
    .unwrap();
    assert!(observed.get());
    assert_eq!(owner.local_keys().unwrap(), &expected);
    let (receipt, result) = owner.record_local_key_creation(descriptor()).unwrap();
    assert!(!receipt.changed());
    assert_eq!(result, LocalKeyObservation::AlreadyRecordedUnverified);
    drop(owner);
    let encoded = payload(&temp);
    assert_eq!(&encoded[8..10], &3_u16.to_be_bytes());
    assert_eq!(
        ControllerCheckpoint::from_bytes(&encoded)
            .unwrap()
            .local_keys(),
        &expected
    );
}

#[test]
fn failed_created_metadata_write_does_not_expose_created_or_erase_pending() {
    let temp = tempfile::tempdir().unwrap();
    let mut owner = fresh(&temp);
    let prepared = owner
        .begin_local_key_creation(handle(), challenge())
        .unwrap();
    assert!(prepared.changed());
    let before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    fs::write(
        temp.path().join(STAGING_FILE_NAME),
        b"synthetic blocked writer",
    )
    .unwrap();
    assert!(matches!(
        owner.record_local_key_creation(descriptor()),
        Err(LocalKeyMutationError::Owner(_))
    ));
    assert!(owner.local_keys().is_err());
    assert!(owner.policy().is_err());
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        before
    );
    // No alias operations exist in this Rust model; native keys are not deleted.
}

#[test]
fn invalid_observation_is_rejected_before_a_store_intent_is_created() {
    let temp = tempfile::tempdir().unwrap();
    let mut owner = fresh(&temp);
    let before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    assert!(matches!(
        owner.record_local_key_creation(descriptor()),
        Err(LocalKeyMutationError::Rejected(_))
    ));
    assert!(owner.local_keys().unwrap().is_empty());
    assert!(owner.policy().is_ok());
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        before
    );
    assert!(!temp.path().join(INTENT_FILE_NAME).exists());
}

#[test]
fn v1_migration_preserves_sections_and_native_preflight_can_refuse_before_rewrite() {
    let temp = tempfile::tempdir().unwrap();
    let inbox = PhoneInbox::with_phone_boot(
        NotificationPolicy::default(),
        CapacityLimits::default(),
        boot(),
    )
    .checkpoint()
    .unwrap()
    .to_bytes()
    .unwrap();
    let history =
        activity_journal::OutcomeHistory::new(activity_journal::OutcomeHistoryLimits::default())
            .to_bytes()
            .unwrap();
    let mut old = b"UACOWNR\0".to_vec();
    old.extend_from_slice(&1_u16.to_be_bytes());
    old.extend_from_slice(&(inbox.len() as u32).to_be_bytes());
    old.extend_from_slice(&(history.len() as u32).to_be_bytes());
    old.extend_from_slice(&inbox);
    old.extend_from_slice(&history);
    drop(SnapshotStore::create_fresh(directory(&temp), &old).unwrap());
    let before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let blocked = DurableInbox::open_existing_host_model_with_key_preflight(
        directory(&temp),
        boot(),
        clock(1),
        |checkpoint| {
            assert!(checkpoint.local_keys().is_empty());
            Err(DurableFault::LocalKeyReconciliationRequired) // Synthetic surviving aliases.
        },
    );
    assert_eq!(
        blocked.unwrap_err().cause(),
        DurableFault::LocalKeyReconciliationRequired
    );
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
    assert_eq!(owner.local_keys().unwrap(), &LocalKeyLedger::default());
    drop(owner);
    let migrated = ControllerCheckpoint::from_bytes(&payload(&temp)).unwrap();
    assert_eq!(migrated.inbox().policy(), &NotificationPolicy::default());
    assert!(migrated.history().records().is_empty());
    assert!(migrated.local_keys().is_empty());
}

#[test]
fn preflight_unwind_does_not_modify_the_prior_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    drop(fresh(&temp));
    let before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let result = std::panic::catch_unwind(|| {
        DurableInbox::open_existing_host_model_with_key_preflight(
            directory(&temp),
            boot(),
            clock(1),
            |_| panic!("synthetic native callback unwind"),
        )
    });
    assert!(result.is_err());
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        before
    );
    assert!(!temp.path().join(INTENT_FILE_NAME).exists());
}
