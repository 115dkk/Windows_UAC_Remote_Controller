// SPDX-License-Identifier: GPL-2.0-or-later
//! Real host files with synthetic signed events and clocks, not Android E2E.

#![cfg(any(windows, target_os = "linux"))]

use std::{
    fs,
    sync::{Arc, Weak},
};

use android_controller::{DurableFailure, DurableFault, DurableInbox, NotificationCleanup};
use approval_protocol::{
    BootEpoch, ChallengeNonce, ExpiryTick, OsSession, PcIdentity, RequestBinding, RequestContent,
    RequestId,
};
use notification_policy::{
    AlertMode, CapacityLimits, ClockReading, DayMask, DropReason, Effect, LocalTime, MonotonicTime,
    NotificationPolicy, RequestOutcome, Schedule, TimeWindow, Weekday, WeeklySchedule,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use phone_request_core::{InboxCheckpointError, InboxClock, InboxFault, PhoneBootId, request_key};
use phone_state_store::{
    Durability, INTENT_FILE_NAME, LOCK_FILE_NAME, NativePrivateDirectory, SNAPSHOT_FILE_NAME,
    STAGING_FILE_NAME, SnapshotStore, StoreError,
};
use service_protocol::{
    ClockCorrelation, ClockProbe, PcEvent, PcPublicKey, RequestResolution, ServiceTick,
    UnsignedPcEvent, VerifiedPcEvent,
};

const MILLI: u64 = 1_000_000;

fn directory(temp: &tempfile::TempDir) -> NativePrivateDirectory {
    NativePrivateDirectory::from_native_app_data(temp.path()).expect("private host test directory")
}

fn boot() -> PhoneBootId {
    PhoneBootId::from_native_boot_count(7).expect("synthetic boot observation")
}

fn clock(milliseconds: u64, minute: u16) -> InboxClock {
    InboxClock::new(
        ClockReading::new(
            MonotonicTime::from_millis(milliseconds),
            LocalTime::new(Weekday::Monday, minute).expect("synthetic local minute"),
        ),
        milliseconds * MILLI,
    )
    .expect("coherent synthetic clock")
}

fn pc() -> PcIdentity {
    PcIdentity::from_bytes([1; 32]).expect("synthetic PC identifier")
}

fn epoch() -> BootEpoch {
    BootEpoch::from_bytes([2; 32]).expect("synthetic service epoch")
}

fn verified(event: PcEvent) -> VerifiedPcEvent {
    // Published synthetic software fixture only, never an enrolled/native key.
    let signer = SigningKey::from_slice(&[7; 32]).expect("synthetic P-256 key");
    let public =
        PcPublicKey::from_sec1_bytes(signer.verifying_key().to_encoded_point(false).as_bytes())
            .expect("synthetic public key");
    let unsigned = UnsignedPcEvent::new(event).expect("valid synthetic event");
    let signature: Signature = signer.sign(&unsigned.signing_bytes());
    unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .expect("synthetic signature")
        .verify(pc(), &public)
        .expect("verified synthetic event")
}

fn correlation(phone_ms: u64, service_ms: u64) -> ClockCorrelation {
    let probe = ClockProbe::start(pc(), phone_ms * MILLI).expect("synthetic native probe");
    let response = verified(PcEvent::Clock {
        pc: pc(),
        epoch: epoch(),
        probe: probe.nonce(),
        sampled_at: ServiceTick::from_nanos_since_epoch(service_ms * MILLI),
    });
    probe
        .complete(&response, phone_ms * MILLI)
        .expect("synthetic clock correlation")
}

fn opened(id: u64, issued_ms: u64, expiry_ms: u64) -> VerifiedPcEvent {
    let mut id_bytes = [0; 32];
    id_bytes[..8].copy_from_slice(&id.to_le_bytes());
    let content = Arc::new(
        RequestContent::new(
            "합성 저장소 테스트 앱",
            "C:\\Synthetic\\durable-inbox-fixture.exe",
            "SYNTHETIC_INERT_BODY_NOT_A_REAL_COMMAND",
        )
        .expect("synthetic inert body"),
    );
    let binding = RequestBinding::new(
        pc(),
        epoch(),
        OsSession::new(1, 7),
        RequestId::from_bytes(id_bytes).expect("synthetic nonzero request ID"),
        ChallengeNonce::from_bytes([5; 32]).expect("synthetic challenge"),
        content.digest(),
        ExpiryTick::from_nanos_since_epoch(expiry_ms * MILLI).expect("positive expiry"),
    );
    verified(PcEvent::Opened {
        binding,
        issued_at: ServiceTick::from_nanos_since_epoch(issued_ms * MILLI),
        content,
    })
}

fn key(event: &VerifiedPcEvent) -> notification_policy::RequestKey {
    let PcEvent::Opened { binding, .. } = event.event() else {
        panic!("synthetic opened event expected");
    };
    request_key(*binding)
}

fn expected_host_durability() -> Durability {
    #[cfg(windows)]
    {
        Durability::FileSyncedOnly
    }
    #[cfg(target_os = "linux")]
    {
        Durability::DirectorySynced
    }
}

fn fresh_owner(temp: &tempfile::TempDir, policy: NotificationPolicy) -> DurableInbox {
    let (owner, initialized) = DurableInbox::create_fresh_host_model(
        directory(temp),
        policy,
        CapacityLimits::default(),
        boot(),
        clock(0, 600),
    )
    .expect("explicit synthetic host-model owner");
    assert!(initialized.update().effects().is_empty());
    owner
}

#[test]
fn policy_only_preflight_does_not_consume_request_recovery_or_committed_outcomes() {
    let temp = tempfile::tempdir().unwrap();
    let mut owner = fresh_owner(&temp, NotificationPolicy::default());
    let event = opened(8_100, 0, 1_000);
    let _committed = owner
        .receive_opened(&event, &mut correlation(0, 0), clock(100, 600))
        .unwrap();
    drop(owner);
    let original = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let error =
        DurableInbox::open_existing_policy_only(directory(&temp), boot(), clock(2_000, 600))
            .unwrap_err();
    assert_eq!(error.cause(), DurableFault::LifecycleIntegrationRequired);
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        original
    );
    assert!(!temp.path().join(INTENT_FILE_NAME).exists());
    // The full lifecycle owner can still recover the actual expiry outcome.
    let (_owner, update) =
        DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(2_000, 600))
            .unwrap();
    assert!(update.update().effects().iter().any(|effect| matches!(
        effect,
        Effect::RecordOutcome {
            outcome: RequestOutcome::ExpiredLocally,
            ..
        }
    )));
}

fn body_weak(event: &VerifiedPcEvent) -> Weak<RequestContent> {
    let PcEvent::Opened { content, .. } = event.event() else {
        panic!("synthetic opened event expected");
    };
    Arc::downgrade(content)
}

fn assert_cleanup(failure: DurableFailure) {
    assert_eq!(
        failure.notification_cleanup(),
        NotificationCleanup::ClearAllOwnedRequestNotifications
    );
}

#[test]
fn committed_off_hours_drop_survives_reopen_without_blocking_a_new_cold_wake_request() {
    let temp = tempfile::Builder::new()
        .prefix("wuac-durable-host-model-")
        .tempdir()
        .expect("isolated host-model directory");
    let policy = NotificationPolicy::new(
        Some(Schedule::Weekly(
            WeeklySchedule::new([
                TimeWindow::new(DayMask::ALL, 600, 660).expect("synthetic time window")
            ])
            .expect("synthetic schedule"),
        )),
        AlertMode::Sound,
    );
    let (mut original, created) = DurableInbox::create_fresh_host_model(
        directory(&temp),
        policy,
        CapacityLimits::default(),
        boot(),
        clock(0, 599),
    )
    .expect("explicit host-model owner");
    assert_eq!(created.receipt().durability(), expected_host_durability());
    let discarded = opened(1, 0, 10_000);
    let committed = original
        .receive_opened(&discarded, &mut correlation(0, 0), clock(100, 599))
        .expect("durable off-hours disposition");
    assert!(committed.receipt().generation() > created.receipt().generation());
    assert!(matches!(
        committed.update().effects(),
        [Effect::Drop {
            reason: DropReason::OutsideAllowedTime,
            ..
        }]
    ));
    drop(original);

    let (mut reopened, recovery) =
        DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(200, 600))
            .expect("reopen the committed host file");
    assert_eq!(recovery.receipt().durability(), expected_host_durability());
    assert!(recovery.update().effects().is_empty());
    let mut fresh_clock = correlation(200, 200);
    let replay = reopened
        .receive_opened(&discarded, &mut fresh_clock, clock(201, 600))
        .expect("durably suppressed old request");
    assert!(!replay.update().effects().iter().any(|effect| matches!(
        effect,
        Effect::Show(_) | Effect::Restore(_) | Effect::RecordOutcome { .. }
    )));
    assert!(
        reopened
            .check_pending(key(&discarded), clock(202, 600))
            .expect("committed current check")
            .check()
            .request()
            .is_none()
    );

    let unseen = opened(2, 150, 10_000);
    let shown = reopened
        .receive_opened(&unseen, &mut fresh_clock, clock(203, 600))
        .expect("commit the new cold-wake request");
    assert!(matches!(shown.update().effects(), [Effect::Show(_)]));
}

#[test]
fn active_recovery_commits_no_realert_restore_with_original_deadline_and_no_saved_body() {
    let temp = tempfile::tempdir().expect("isolated host-model directory");
    let mut owner = fresh_owner(&temp, NotificationPolicy::default());
    let event = opened(3, 0, 1_000);
    let weak = body_weak(&event);
    let admitted = owner
        .receive_opened(&event, &mut correlation(0, 0), clock(1, 600))
        .expect("commit initial active request");
    assert!(matches!(admitted.update().effects(), [Effect::Show(_)]));
    let original_key = key(&event);
    drop(owner);
    drop(event);
    assert!(
        weak.upgrade().is_none(),
        "the file and receipt cannot retain an old body"
    );

    let (mut reopened, recovery) =
        DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(200, 600))
            .expect("restore metadata only");
    assert!(recovery.update().effects().is_empty());
    assert_eq!(reopened.counts().unwrap().recovering(), 1);
    assert_eq!(reopened.counts().unwrap().retained_bodies(), 0);
    assert!(
        reopened
            .check_pending(original_key, clock(200, 600))
            .expect("commit recovering check")
            .check()
            .request()
            .is_none()
    );

    let reverified = opened(3, 0, 1_000);
    let restored = reopened
        .receive_opened(&reverified, &mut correlation(200, 50), clock(201, 600))
        .expect("commit exact reverified body recovery");
    assert!(
        matches!(restored.update().effects(), [Effect::Restore(pending)]
        if pending.expires_at.as_millis() == 1_000)
    );
    assert_eq!(reopened.counts().unwrap().recovering(), 0);
    assert_eq!(reopened.counts().unwrap().active(), 1);
    assert_eq!(reopened.next_deadline_nanos().unwrap(), Some(1_000 * MILLI));
    // Restore is the no-realert effect; the saved preference remains unchanged.
    assert_eq!(reopened.policy().unwrap().alert(), AlertMode::Sound);
}

#[test]
fn checked_view_keeps_original_expiry_and_expiry_is_committed_before_body_removal_returns() {
    let temp = tempfile::tempdir().expect("isolated host-model directory");
    let mut owner = fresh_owner(&temp, NotificationPolicy::default());
    let event = opened(4, 0, 1_000);
    let original_key = key(&event);
    let weak = body_weak(&event);
    let admitted = owner
        .receive_opened(&event, &mut correlation(0, 0), clock(1, 600))
        .unwrap();
    let checked = owner.check_pending(original_key, clock(999, 600)).unwrap();
    let request = checked
        .check()
        .request()
        .expect("pre-expiry committed view");
    assert_eq!(
        request.original_window().phone_expiry_nanos(),
        1_000 * MILLI
    );
    assert!(checked.receipt().generation() > admitted.receipt().generation());
    drop(checked);
    drop(event);
    assert!(weak.upgrade().is_some());

    let expired = owner
        .check_pending(original_key, clock(1_000, 600))
        .unwrap();
    assert!(expired.check().request().is_none());
    assert!(
        expired
            .check()
            .update()
            .effects()
            .iter()
            .any(|effect| matches!(
                effect,
                Effect::RecordOutcome {
                    outcome: RequestOutcome::ExpiredLocally,
                    ..
                }
            ))
    );
    assert!(weak.upgrade().is_none());
    drop(owner);
    let (mut reopened, _) =
        DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(1_001, 600))
            .unwrap();
    assert_eq!(reopened.counts().unwrap().active(), 0);
    assert!(
        reopened
            .check_pending(original_key, clock(1_001, 600))
            .unwrap()
            .check()
            .request()
            .is_none()
    );
}

#[test]
fn no_op_poll_check_policy_and_source_observation_explicitly_finish_their_intents() {
    let temp = tempfile::tempdir().expect("isolated host-model directory");
    let mut owner = fresh_owner(&temp, NotificationPolicy::default());
    let first = owner.poll(clock(0, 600)).unwrap();
    assert!(!first.receipt().changed());
    let unchanged = owner
        .check_pending(key(&opened(5, 0, 1_000)), clock(0, 600))
        .unwrap();
    assert!(!unchanged.receipt().changed());
    assert_eq!(
        unchanged.receipt().generation(),
        first.receipt().generation()
    );
    assert!(unchanged.check().request().is_none());
    let policy = owner.policy().unwrap().clone();
    let saved = owner.update_policy(policy, clock(0, 600)).unwrap();
    assert!(!saved.receipt().changed());
    let source = correlation(0, 0);
    let observed = owner.observe_service_clock(&source, clock(0, 600)).unwrap();
    assert!(observed.receipt().changed());
    let repeated = owner.observe_service_clock(&source, clock(0, 600)).unwrap();
    assert!(!repeated.receipt().changed());
    assert_eq!(
        repeated.receipt().generation(),
        observed.receipt().generation()
    );
    assert!(!temp.path().join(INTENT_FILE_NAME).exists());
    assert!(!temp.path().join(STAGING_FILE_NAME).exists());
    drop(owner);
    let (reopened, _) =
        DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(1, 600))
            .expect("all no-op intents completed");
    assert_eq!(reopened.counts().unwrap().sources(), 1);
}

#[test]
fn committed_policy_is_the_only_policy_authority_on_reopen() {
    let temp = tempfile::tempdir().expect("isolated host-model directory");
    let mut owner = fresh_owner(&temp, NotificationPolicy::default());
    let disabled = NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent);
    let saved = owner
        .update_policy(disabled.clone(), clock(10, 600))
        .unwrap();
    assert!(saved.receipt().changed());
    assert_eq!(owner.policy().unwrap(), &disabled);
    drop(owner);
    // Open accepts no external/default policy that could overwrite this snapshot.
    let (mut reopened, _) =
        DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(11, 600)).unwrap();
    assert_eq!(reopened.policy().unwrap(), &disabled);
    let received = reopened
        .receive_opened(
            &opened(6, 0, 1_000),
            &mut correlation(11, 11),
            clock(12, 600),
        )
        .unwrap();
    assert!(matches!(
        received.update().effects(),
        [Effect::Drop {
            reason: DropReason::NotificationsDisabled,
            ..
        }]
    ));
}

#[test]
fn verified_pc_resolution_is_committed_before_returning_its_outcome() {
    let temp = tempfile::tempdir().expect("isolated host-model directory");
    let mut owner = fresh_owner(&temp, NotificationPolicy::default());
    let event = opened(7, 0, 1_000);
    let mut source = correlation(0, 0);
    let admitted = owner
        .receive_opened(&event, &mut source, clock(1, 600))
        .unwrap();
    let PcEvent::Opened {
        binding, issued_at, ..
    } = event.event()
    else {
        unreachable!()
    };
    let resolution = verified(PcEvent::Resolved {
        binding: *binding,
        issued_at: *issued_at,
        outcome: RequestResolution::Cancelled,
    });
    let completed = owner
        .resolve_pc(&resolution, &mut source, clock(2, 600))
        .unwrap();
    assert!(completed.receipt().generation() > admitted.receipt().generation());
    assert!(completed.update().effects().iter().any(|effect| matches!(
        effect,
        Effect::RecordOutcome {
            outcome: RequestOutcome::CancelledByPc,
            ..
        }
    )));
    drop(owner);
    let (mut reopened, _) =
        DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(3, 600)).unwrap();
    let replay = reopened
        .receive_opened(&event, &mut correlation(3, 3), clock(4, 600))
        .unwrap();
    assert!(matches!(
        replay.update().effects(),
        [Effect::Drop {
            reason: DropReason::PreviouslySuppressed,
            ..
        }]
    ));
}

#[test]
fn committed_source_watermark_survives_reopen_and_rejects_an_older_request() {
    let temp = tempfile::tempdir().expect("isolated host-model directory");
    let mut owner = fresh_owner(&temp, NotificationPolicy::default());
    let updated = owner
        .observe_service_clock(&correlation(100, 1_000), clock(100, 600))
        .unwrap();
    assert!(updated.receipt().changed());
    drop(owner);
    let (mut reopened, _) =
        DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(200, 600)).unwrap();
    // A historically verified but older correlation cannot reduce the watermark.
    let received = reopened
        .receive_opened(
            &opened(8, 0, 500),
            &mut correlation(200, 0),
            clock(201, 600),
        )
        .unwrap();
    assert!(matches!(
        received.update().effects(),
        [Effect::Drop {
            reason: DropReason::Expired,
            ..
        }]
    ));
}

#[test]
fn failed_staging_begin_is_unaccepted_preserves_prior_file_and_latches_all_access() {
    let temp = tempfile::tempdir().expect("isolated host-model directory");
    let mut owner = fresh_owner(&temp, NotificationPolicy::default());
    let prior = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let foreign = b"synthetic foreign staging must not be removed";
    fs::write(temp.path().join(STAGING_FILE_NAME), foreign).unwrap();
    let failure = owner
        .receive_opened(&opened(9, 0, 1_000), &mut correlation(0, 0), clock(1, 600))
        .expect_err("no accepted disposition before the intent barrier");
    let cause = DurableFault::Storage(StoreError::RecoveryRequired);
    assert_eq!(failure.cause(), cause);
    assert_cleanup(failure);
    assert_eq!(owner.fault(), Some(cause));
    assert_eq!(owner.policy(), Err(cause));
    assert_eq!(owner.counts(), Err(cause));
    assert_eq!(owner.next_deadline_nanos(), Err(cause));
    assert_eq!(owner.limits(), Err(cause));
    assert_eq!(owner.is_quarantined(), Err(cause));
    assert_eq!(owner.inbox_fault(), Err(cause));
    assert_cleanup(
        owner
            .poll(clock(2, 600))
            .expect_err("fault is irreversible"),
    );
    assert_cleanup(
        owner
            .update_policy(NotificationPolicy::default(), clock(2, 600))
            .unwrap_err(),
    );
    assert_cleanup(
        owner
            .check_pending(key(&opened(9, 0, 1_000)), clock(2, 600))
            .unwrap_err(),
    );
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        prior
    );
    assert_eq!(
        fs::read(temp.path().join(STAGING_FILE_NAME)).unwrap(),
        foreign
    );
    assert!(!temp.path().join(INTENT_FILE_NAME).exists());
    assert_eq!(
        SnapshotStore::open_existing(directory(&temp)).err(),
        Some(StoreError::WriterLocked)
    );
    drop(owner);
    assert_eq!(
        SnapshotStore::open_existing(directory(&temp)).err(),
        Some(StoreError::RecoveryRequired)
    );
}

#[test]
fn failed_intent_begin_does_not_accept_a_noop_or_clean_foreign_intent() {
    let temp = tempfile::tempdir().expect("isolated host-model directory");
    let mut owner = fresh_owner(&temp, NotificationPolicy::default());
    let prior = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let foreign = b"synthetic foreign intent";
    fs::write(temp.path().join(INTENT_FILE_NAME), foreign).unwrap();
    let failure = owner
        .poll(clock(0, 600))
        .expect_err("even no-ops must reserve successfully");
    assert_eq!(
        failure.cause(),
        DurableFault::Storage(StoreError::RecoveryRequired)
    );
    assert_cleanup(failure);
    assert_eq!(
        fs::read(temp.path().join(INTENT_FILE_NAME)).unwrap(),
        foreign
    );
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        prior
    );
}

#[test]
fn missing_saved_state_never_becomes_a_fresh_owner() {
    let temp = tempfile::tempdir().expect("isolated host-model directory");
    let failure = DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(0, 600))
        .expect_err("missing existing state cannot default to fresh state");
    assert_eq!(
        failure.cause(),
        DurableFault::Storage(StoreError::MissingState)
    );
    assert_cleanup(failure);
    assert!(!temp.path().join(SNAPSHOT_FILE_NAME).exists());
    assert!(!temp.path().join(LOCK_FILE_NAME).exists());
}

#[test]
fn invalid_domain_checkpoint_fails_after_reserved_intent_without_defaulting_policy() {
    let temp = tempfile::tempdir().expect("isolated host-model directory");
    let (store, receipt) =
        SnapshotStore::create_fresh(directory(&temp), b"invalid synthetic domain payload").unwrap();
    assert_eq!(receipt.durability(), expected_host_durability());
    drop(store);
    let prior = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let failure = DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(0, 600))
        .expect_err("valid byte frame is not valid domain state");
    assert_eq!(
        failure.cause(),
        DurableFault::Checkpoint(InboxCheckpointError::InvalidState)
    );
    assert_cleanup(failure);
    assert!(temp.path().join(INTENT_FILE_NAME).exists());
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        prior
    );
    assert_eq!(
        SnapshotStore::open_existing(directory(&temp)).err(),
        Some(StoreError::RecoveryRequired)
    );
}

#[test]
fn domain_clock_fault_is_committed_and_not_confused_with_an_uncertain_owner_failure() {
    let temp = tempfile::tempdir().expect("isolated host-model directory");
    let mut owner = fresh_owner(&temp, NotificationPolicy::default());
    let admitted = owner
        .receive_opened(
            &opened(10, 0, 1_000),
            &mut correlation(0, 0),
            clock(100, 600),
        )
        .unwrap();
    let faulted = owner
        .poll(clock(99, 600))
        .expect("domain fault must itself be committed");
    assert!(faulted.receipt().generation() > admitted.receipt().generation());
    assert_eq!(
        faulted.update().fault(),
        Some(InboxFault::NativeClockRegressed)
    );
    assert_eq!(owner.fault(), None);
    assert_eq!(
        owner.inbox_fault().unwrap(),
        Some(InboxFault::NativeClockRegressed)
    );
    assert_eq!(owner.counts().unwrap().active(), 0);
    drop(owner);
    let (reopened, recovery) =
        DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(200, 600)).unwrap();
    assert_eq!(
        recovery.update().fault(),
        Some(InboxFault::NativeClockRegressed)
    );
    assert_eq!(
        reopened.inbox_fault().unwrap(),
        Some(InboxFault::NativeClockRegressed)
    );
}

#[test]
fn debug_never_discloses_native_path_checkpoint_or_request_body() {
    let temp = tempfile::tempdir().expect("isolated host-model directory");
    let mut owner = fresh_owner(&temp, NotificationPolicy::default());
    let event = opened(11, 0, 1_000);
    let committed = owner
        .receive_opened(&event, &mut correlation(0, 0), clock(1, 600))
        .unwrap();
    let checked = owner.check_pending(key(&event), clock(2, 600)).unwrap();
    let visible = format!("{owner:?} {committed:?} {checked:?}");
    assert!(!visible.contains("SYNTHETIC_INERT_BODY"));
    assert!(!visible.contains("durable-inbox-fixture.exe"));
    assert!(!visible.contains(&temp.path().to_string_lossy().to_string()));
}

#[cfg(windows)]
fn block_snapshot_rename(temp: &tempfile::TempDir) -> fs::File {
    use std::os::windows::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .share_mode(0x0003)
        .open(temp.path().join(SNAPSHOT_FILE_NAME))
        .expect("synthetic host handle allows reads/writes but denies share-delete")
}

#[cfg(windows)]
#[test]
fn failed_receive_commit_drops_candidate_body_and_returns_no_show_or_accepted_drop() {
    let temp = tempfile::tempdir().expect("isolated Windows host-model directory");
    let mut owner = fresh_owner(&temp, NotificationPolicy::default());
    let prior = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let blocker = block_snapshot_rename(&temp);
    let event = opened(12, 0, 1_000);
    let weak = body_weak(&event);
    let failure = owner
        .receive_opened(&event, &mut correlation(0, 0), clock(1, 600))
        .expect_err("rename failure cannot return the candidate Show");
    assert_eq!(
        failure.cause(),
        DurableFault::Storage(StoreError::CommitUncertain)
    );
    assert_cleanup(failure);
    drop(event);
    assert!(
        weak.upgrade().is_none(),
        "no candidate body remains in the failed owner"
    );
    assert!(owner.counts().is_err());
    // Specific injected blocker preserves the old file; other uncertain failures
    // may already have replaced it and must never be called a rollback.
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        prior
    );
    assert!(temp.path().join(INTENT_FILE_NAME).exists());
    assert!(temp.path().join(STAGING_FILE_NAME).exists());
    drop(blocker);
    drop(owner);
    assert_eq!(
        SnapshotStore::open_existing(directory(&temp)).err(),
        Some(StoreError::RecoveryRequired)
    );
}

#[cfg(windows)]
#[test]
fn failed_pending_check_commit_releases_both_owned_and_candidate_view_references() {
    let temp = tempfile::tempdir().expect("isolated Windows host-model directory");
    let mut owner = fresh_owner(&temp, NotificationPolicy::default());
    let event = opened(13, 0, 1_000);
    let weak = body_weak(&event);
    let admitted = owner
        .receive_opened(&event, &mut correlation(0, 0), clock(1, 600))
        .unwrap();
    assert!(matches!(admitted.update().effects(), [Effect::Show(_)]));
    let original_key = key(&event);
    drop(event);
    let prior = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let blocker = block_snapshot_rename(&temp);
    let failure = owner
        .check_pending(original_key, clock(2, 600))
        .expect_err("body view must not escape before its clock transition commits");
    assert_cleanup(failure);
    assert_eq!(
        failure.cause(),
        DurableFault::Storage(StoreError::CommitUncertain)
    );
    assert!(weak.upgrade().is_none());
    assert!(owner.policy().is_err());
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        prior
    );
    drop(blocker);
}

#[cfg(windows)]
#[test]
fn failed_recovery_commit_returns_no_restore_and_releases_reverified_body() {
    let temp = tempfile::tempdir().expect("isolated Windows host-model directory");
    let mut original = fresh_owner(&temp, NotificationPolicy::default());
    let initial = opened(14, 0, 1_000);
    let admitted = original
        .receive_opened(&initial, &mut correlation(0, 0), clock(1, 600))
        .unwrap();
    assert!(matches!(admitted.update().effects(), [Effect::Show(_)]));
    drop(original);
    drop(initial);
    let (mut reopened, _) =
        DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(200, 600)).unwrap();
    assert_eq!(reopened.counts().unwrap().recovering(), 1);
    let prior = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let blocker = block_snapshot_rename(&temp);
    let reverified = opened(14, 0, 1_000);
    let weak = body_weak(&reverified);
    let failure = reopened
        .receive_opened(&reverified, &mut correlation(200, 50), clock(201, 600))
        .expect_err("a candidate Restore is not a committed recovery");
    assert_eq!(
        failure.cause(),
        DurableFault::Storage(StoreError::CommitUncertain)
    );
    assert_cleanup(failure);
    drop(reverified);
    assert!(weak.upgrade().is_none());
    assert!(reopened.counts().is_err());
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        prior
    );
    drop(blocker);
}

#[cfg(windows)]
#[test]
fn failed_policy_commit_never_exposes_the_candidate_as_persisted_policy() {
    let temp = tempfile::tempdir().expect("isolated Windows host-model directory");
    let mut owner = fresh_owner(&temp, NotificationPolicy::default());
    let prior = fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap();
    let blocker = block_snapshot_rename(&temp);
    let failure = owner
        .update_policy(
            NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent),
            clock(1, 600),
        )
        .expect_err("candidate policy could not replace prior snapshot");
    assert_cleanup(failure);
    assert_eq!(
        owner.policy(),
        Err(DurableFault::Storage(StoreError::CommitUncertain))
    );
    assert_eq!(
        fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        prior
    );
    drop(blocker);
}

#[cfg(windows)]
#[test]
fn native_factories_reject_actual_file_only_receipts_without_model_fallback() {
    let temp = tempfile::tempdir().expect("isolated Windows host-model directory");
    let failure = DurableInbox::create_fresh(
        directory(&temp),
        NotificationPolicy::default(),
        CapacityLimits::default(),
        boot(),
        clock(0, 600),
    )
    .expect_err("native creation requires a real directory-sync receipt");
    assert_eq!(
        failure.cause(),
        DurableFault::DirectorySynchronizationRequired
    );
    assert_cleanup(failure);
    // Creation rejection may leave a completed body-free initial snapshot. Only
    // this explicitly named model factory is allowed to inspect it in this test.
    let (model, opened) =
        DurableInbox::open_existing_host_model(directory(&temp), boot(), clock(0, 600)).unwrap();
    assert_eq!(opened.receipt().durability(), Durability::FileSyncedOnly);
    assert_eq!(model.counts().unwrap().retained(), 0);
    drop(model);
    let failure = DurableInbox::open_existing(directory(&temp), boot(), clock(1, 600))
        .expect_err("native reopen cannot weaken durability either");
    assert_eq!(
        failure.cause(),
        DurableFault::DirectorySynchronizationRequired
    );
    assert_cleanup(failure);
}

#[cfg(target_os = "linux")]
#[test]
fn native_factory_uses_real_directory_sync_receipts_on_linux_host_files() {
    let temp = tempfile::tempdir().expect("isolated Linux host-model directory");
    let (owner, created) = DurableInbox::create_fresh(
        directory(&temp),
        NotificationPolicy::default(),
        CapacityLimits::default(),
        boot(),
        clock(0, 600),
    )
    .expect("actual host file and directory synchronization");
    assert_eq!(created.receipt().durability(), Durability::DirectorySynced);
    drop(owner);
    let (_, opened) = DurableInbox::open_existing(directory(&temp), boot(), clock(1, 600)).unwrap();
    assert_eq!(opened.receipt().durability(), Durability::DirectorySynced);
}
