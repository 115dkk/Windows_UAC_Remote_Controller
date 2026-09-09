// SPDX-License-Identifier: GPL-2.0-or-later
//! Real isolated host stores and synthetic public keys/signed request fixtures.
//! No Android Keystore, enrollment, live intake, notification or native proof.
#![cfg(any(windows, target_os = "linux"))]

use android_controller::{
    ControllerCheckpointError, DurableFault, DurableInbox, LocalAttestationChallenge,
    LocalKeyHandle, LocalKeySetDescriptor, NotificationCleanup,
};
use approval_protocol::{
    BootEpoch, ChallengeNonce, ExpiryTick, OsSession, PcIdentity, RequestBinding, RequestContent,
    RequestId,
};
use notification_policy::{
    CapacityLimits, ClockReading, Effect, LocalTime, MonotonicTime, NotificationPolicy,
    RequestOutcome, Weekday,
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use phone_request_core::{InboxCheckpointError, InboxClock, PhoneBootId, request_key};
use phone_state_store::{
    Durability, INTENT_FILE_NAME, NativePrivateDirectory, SNAPSHOT_FILE_NAME, STAGING_FILE_NAME,
    SnapshotStore, StoreError,
};
use secure_channel::TlsPublicKey;
use service_protocol::{
    ClockCorrelation, ClockProbe, PcEvent, PcPublicKey, ServiceTick, UnsignedPcEvent,
    VerifiedPcEvent,
};
use std::{cell::Cell, fs, sync::Arc};

const MILLI: u64 = 1_000_000;
fn directory(temp: &tempfile::TempDir) -> NativePrivateDirectory {
    NativePrivateDirectory::from_native_app_data(temp.path()).unwrap()
}
fn boot() -> PhoneBootId {
    PhoneBootId::from_native_boot_count(2).unwrap()
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
fn host_durability() -> Durability {
    #[cfg(windows)]
    {
        Durability::FileSyncedOnly
    }
    #[cfg(target_os = "linux")]
    {
        Durability::DirectorySynced
    }
}
fn public(seed: u8) -> TlsPublicKey {
    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
    let point =
        p256::PublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    TlsPublicKey::from_spki_der(point.to_public_key_der().unwrap().as_bytes()).unwrap()
}
fn descriptor() -> LocalKeySetDescriptor {
    LocalKeySetDescriptor::new(
        LocalKeyHandle::from_bytes([1; 32]).unwrap(),
        LocalAttestationChallenge::from_bytes([2; 32]).unwrap(),
        public(3),
        public(4),
        public(5),
    )
    .unwrap()
}
fn fresh(temp: &tempfile::TempDir) -> DurableInbox {
    let (mut owner, initial) = DurableInbox::create_fresh_host_model(
        directory(temp),
        NotificationPolicy::default(),
        CapacityLimits::default(),
        boot(),
        clock(0),
    )
    .unwrap();
    assert!(initial.update().effects().is_empty());
    let keys = descriptor();
    let _ = owner
        .begin_local_key_creation(keys.handle(), keys.challenge())
        .unwrap();
    let _ = owner.record_local_key_creation(keys).unwrap();
    owner
}
fn assert_dirty_preserved(temp: &tempfile::TempDir, before: &[u8]) {
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        before
    );
    assert!(temp.path().join(INTENT_FILE_NAME).is_file());
    assert_eq!(
        SnapshotStore::open_existing(directory(temp)).unwrap_err(),
        StoreError::RecoveryRequired
    );
}
fn pc() -> PcIdentity {
    PcIdentity::from_bytes([11; 32]).unwrap()
}
fn epoch() -> BootEpoch {
    BootEpoch::from_bytes([12; 32]).unwrap()
}
fn verified(event: PcEvent) -> VerifiedPcEvent {
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let public =
        PcPublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    let unsigned = UnsignedPcEvent::new(event).unwrap();
    let signature: Signature = key.sign(&unsigned.signing_bytes());
    unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
        .verify(pc(), &public)
        .unwrap()
}
fn correlation() -> ClockCorrelation {
    let probe = ClockProbe::start(pc(), 0).unwrap();
    let reply = verified(PcEvent::Clock {
        pc: pc(),
        epoch: epoch(),
        probe: probe.nonce(),
        sampled_at: ServiceTick::from_nanos_since_epoch(0),
    });
    probe.complete(&reply, 0).unwrap()
}
fn opened() -> (VerifiedPcEvent, RequestBinding) {
    let content = Arc::new(
        RequestContent::new(
            "Synthetic full preflight request",
            "C:\\Synthetic\\preflight.exe",
            "INERT_PREFLIGHT_BODY_NOT_NATIVE_PROOF",
        )
        .unwrap(),
    );
    let binding = RequestBinding::new(
        pc(),
        epoch(),
        OsSession::new(1, 7),
        RequestId::from_bytes([13; 32]).unwrap(),
        ChallengeNonce::from_bytes([14; 32]).unwrap(),
        content.digest(),
        ExpiryTick::from_nanos_since_epoch(1_000 * MILLI).unwrap(),
    );
    (
        verified(PcEvent::Opened {
            binding,
            issued_at: ServiceTick::from_nanos_since_epoch(0),
            content,
        }),
        binding,
    )
}
fn request_store(temp: &tempfile::TempDir) -> RequestBinding {
    let mut owner = fresh(temp);
    let (event, binding) = opened();
    let update = owner
        .receive_opened(&event, &mut correlation(), clock(10))
        .unwrap();
    assert!(
        update
            .update()
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
    assert_eq!(owner.counts().unwrap().active(), 1);
    drop(owner);
    binding
}

#[test]
fn full_preflight_holds_writer_lock_and_intent_before_restore_and_commit() {
    let temp = tempfile::tempdir().unwrap();
    drop(fresh(&temp));
    let before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let calls = Cell::new(0);
    let next_boot = PhoneBootId::from_native_boot_count(3).unwrap();
    let (owner, update) = DurableInbox::open_existing_full_host_model_with_key_preflight(
        directory(&temp),
        next_boot,
        clock(1),
        |checkpoint| {
            calls.set(calls.get() + 1);
            assert!(temp.path().join(INTENT_FILE_NAME).is_file());
            assert_eq!(
                SnapshotStore::open_existing(directory(&temp)).unwrap_err(),
                StoreError::WriterLocked
            );
            assert_eq!(
                fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
                before
            );
            assert_eq!(
                checkpoint.inbox().phone_boot(),
                boot(),
                "preflight sees original, not restored boot"
            );
            assert_eq!(
                checkpoint
                    .local_keys()
                    .get(descriptor().handle())
                    .unwrap()
                    .descriptor(),
                Some(&descriptor())
            );
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(update.receipt().durability(), host_durability());
    assert!(update.update().effects().is_empty());
    assert!(update.update().fault().is_none());
    assert!(!temp.path().join(INTENT_FILE_NAME).exists());
    assert_eq!(
        owner
            .local_keys()
            .unwrap()
            .get(descriptor().handle())
            .unwrap()
            .descriptor(),
        Some(&descriptor())
    );
    drop(owner);
    let store = SnapshotStore::open_existing(directory(&temp)).unwrap();
    let stored =
        android_controller::ControllerCheckpoint::from_bytes(store.snapshot().unwrap()).unwrap();
    assert_eq!(stored.inbox().phone_boot(), next_boot);
}

#[test]
fn rejected_full_preflight_precedes_restore_failure_and_leaves_intent_without_owner() {
    let temp = tempfile::tempdir().unwrap();
    let mut owner = fresh(&temp);
    let _ = owner.poll(clock(10)).unwrap();
    drop(owner);
    let before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let calls = Cell::new(0);
    let failure = DurableInbox::open_existing_full_host_model_with_key_preflight(
        directory(&temp),
        boot(),
        clock(9),
        |_| {
            calls.set(calls.get() + 1);
            assert!(temp.path().join(INTENT_FILE_NAME).is_file());
            Err(DurableFault::NativeLocalKeysUnavailable)
        },
    )
    .unwrap_err();
    assert_eq!(calls.get(), 1);
    assert_eq!(
        failure.cause(),
        DurableFault::NativeLocalKeysUnavailable,
        "callback precedes regressed-clock restore"
    );
    assert_eq!(
        failure.notification_cleanup(),
        NotificationCleanup::ClearAllOwnedRequestNotifications
    );
    assert_dirty_preserved(&temp, &before);
    let retry = DurableInbox::open_existing_full_host_model_with_key_preflight(
        directory(&temp),
        boot(),
        clock(11),
        |_| {
            calls.set(calls.get() + 1);
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(
        retry.cause(),
        DurableFault::Storage(StoreError::RecoveryRequired)
    );
    assert_eq!(
        calls.get(),
        1,
        "dirty full preflight is not retried as policy/fresh state"
    );
}

#[test]
fn accepted_preflight_still_returns_no_owner_when_original_restore_clock_regresses() {
    let temp = tempfile::tempdir().unwrap();
    let mut owner = fresh(&temp);
    let _ = owner.poll(clock(10)).unwrap();
    drop(owner);
    let before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let called = Cell::new(false);
    let failure = DurableInbox::open_existing_full_host_model_with_key_preflight(
        directory(&temp),
        boot(),
        clock(9),
        |_| {
            called.set(true);
            Ok(())
        },
    )
    .unwrap_err();
    assert!(called.get());
    assert_eq!(
        failure.cause(),
        DurableFault::Checkpoint(InboxCheckpointError::ClockRegressed)
    );
    assert_dirty_preserved(&temp, &before);
}

#[test]
fn invalid_domain_payload_reserves_intent_but_never_calls_key_preflight() {
    let temp = tempfile::tempdir().unwrap();
    drop(
        SnapshotStore::create_fresh(directory(&temp), b"synthetic invalid domain payload").unwrap(),
    );
    let before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let called = Cell::new(false);
    let failure = DurableInbox::open_existing_full_host_model_with_key_preflight(
        directory(&temp),
        boot(),
        clock(0),
        |_| {
            called.set(true);
            Ok(())
        },
    )
    .unwrap_err();
    assert!(!called.get());
    assert_eq!(
        failure.cause(),
        DurableFault::Composite(ControllerCheckpointError::InvalidEncoding)
    );
    assert_eq!(
        failure.notification_cleanup(),
        NotificationCleanup::ClearAllOwnedRequestNotifications
    );
    assert_dirty_preserved(&temp, &before);
}

#[test]
fn corrupt_outer_store_fails_before_domain_intent_and_preflight() {
    let temp = tempfile::tempdir().unwrap();
    drop(fresh(&temp));
    let path = temp.path().join(SNAPSHOT_FILE_NAME);
    let mut corrupt = fs::read(&path).unwrap();
    corrupt[0] ^= 1;
    fs::write(&path, &corrupt).unwrap();
    let called = Cell::new(false);
    let failure = DurableInbox::open_existing_full_host_model_with_key_preflight(
        directory(&temp),
        boot(),
        clock(0),
        |_| {
            called.set(true);
            Ok(())
        },
    )
    .unwrap_err();
    assert!(!called.get());
    assert_eq!(
        failure.cause(),
        DurableFault::Storage(StoreError::CorruptSnapshot)
    );
    assert!(!temp.path().join(INTENT_FILE_NAME).exists());
    assert_eq!(fs::read(path).unwrap(), corrupt);
}

#[test]
fn callback_unwind_retains_full_open_intent_and_releases_its_writer_lock() {
    let temp = tempfile::tempdir().unwrap();
    drop(fresh(&temp));
    let before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let result = std::panic::catch_unwind(|| {
        DurableInbox::open_existing_full_host_model_with_key_preflight(
            directory(&temp),
            boot(),
            clock(1),
            |_| {
                assert!(temp.path().join(INTENT_FILE_NAME).is_file());
                panic!("synthetic native preflight unwind");
            },
        )
    });
    assert!(result.is_err());
    assert_dirty_preserved(&temp, &before); // RecoveryRequired, not a leaked WriterLocked.
}

#[test]
fn old_policy_only_factory_stays_closed_while_full_factory_recovers_request_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let binding = request_store(&temp);
    let before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let old_called = Cell::new(false);
    let failure = DurableInbox::open_existing_host_model_with_key_preflight(
        directory(&temp),
        boot(),
        clock(11),
        |_| {
            old_called.set(true);
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(failure.cause(), DurableFault::LifecycleIntegrationRequired);
    assert!(!old_called.get());
    assert!(!temp.path().join(INTENT_FILE_NAME).exists());
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        before
    );

    let (mut owner, restored) = DurableInbox::open_existing_full_host_model_with_key_preflight(
        directory(&temp),
        boot(),
        clock(11),
        |checkpoint| {
            assert!(!checkpoint.inbox().is_policy_only());
            assert!(temp.path().join(INTENT_FILE_NAME).is_file());
            assert!(
                checkpoint
                    .local_keys()
                    .get(descriptor().handle())
                    .unwrap()
                    .descriptor()
                    .is_some()
            );
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(owner.counts().unwrap().retained(), 1);
    assert_eq!(owner.counts().unwrap().recovering(), 1);
    assert_eq!(owner.counts().unwrap().retained_bodies(), 0);
    assert!(
        restored
            .update()
            .effects()
            .iter()
            .all(|effect| !matches!(effect, Effect::Show(_) | Effect::Restore(_)))
    );
    assert!(!temp.path().join(INTENT_FILE_NAME).exists());
    let pending = owner
        .check_pending(request_key(binding), clock(12))
        .unwrap();
    assert!(
        pending.check().request().is_none(),
        "stored metadata does not restore a usable body"
    );
    drop(owner);
    let (owner, expired) = DurableInbox::open_existing_full_host_model_with_key_preflight(
        directory(&temp),
        boot(),
        clock(1_000),
        |_| Ok(()),
    )
    .unwrap();
    assert!(expired.update().effects().iter().any(|effect| matches!(
        effect,
        Effect::RecordOutcome {
            outcome: RequestOutcome::ExpiredLocally,
            ..
        }
    )));
    assert_eq!(owner.pending_outcomes().unwrap().len(), 1);
}

#[test]
fn failed_commit_after_preflight_exposes_no_candidate_expiry_effects() {
    let temp = tempfile::tempdir().unwrap();
    let _ = request_store(&temp);
    let before = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let failure = DurableInbox::open_existing_full_host_model_with_key_preflight(
        directory(&temp),
        boot(),
        clock(1_000),
        |_| {
            // Test-only filesystem interference at the system boundary, not
            // supported behavior for a production native-key callback.
            fs::write(
                temp.path().join(STAGING_FILE_NAME),
                b"synthetic commit blocker",
            )
            .unwrap();
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(
        failure.cause(),
        DurableFault::Storage(StoreError::RecoveryRequired)
    );
    assert_eq!(
        failure.notification_cleanup(),
        NotificationCleanup::ClearAllOwnedRequestNotifications
    );
    assert_dirty_preserved(&temp, &before);
}

#[test]
fn native_full_factory_requires_real_directory_synced_receipts_without_host_fallback() {
    let temp = tempfile::tempdir().unwrap();
    drop(fresh(&temp));
    let called = Cell::new(false);
    let result =
        DurableInbox::open_existing_with_key_preflight(directory(&temp), boot(), clock(1), |_| {
            called.set(true);
            assert!(temp.path().join(INTENT_FILE_NAME).is_file());
            Ok(())
        });
    assert!(called.get());
    #[cfg(windows)]
    {
        let failure = result.unwrap_err();
        assert_eq!(
            failure.cause(),
            DurableFault::DirectorySynchronizationRequired
        );
        assert_eq!(
            failure.notification_cleanup(),
            NotificationCleanup::ClearAllOwnedRequestNotifications
        );
        // The weak-profile commit may already have completed. No old-snapshot
        // rollback or owner/effect publication is inferred from rejection.
    }
    #[cfg(target_os = "linux")]
    {
        let (owner, update) = result.unwrap();
        assert_eq!(update.receipt().durability(), Durability::DirectorySynced);
        assert!(update.update().effects().is_empty());
        drop(owner);
    }
}
