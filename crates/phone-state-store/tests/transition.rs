// SPDX-License-Identifier: GPL-2.0-or-later

use std::fs;

use phone_state_store::{
    INTENT_FILE_NAME, MAX_SNAPSHOT_BYTES, NativePrivateDirectory, SNAPSHOT_FILE_NAME,
    STAGING_FILE_NAME, SnapshotStore, StoreError,
};

fn directory(temp: &tempfile::TempDir) -> NativePrivateDirectory {
    NativePrivateDirectory::from_native_app_data(temp.path()).expect("private test directory")
}

#[test]
fn an_uncommitted_transition_faults_the_owner_and_blocks_reopening() {
    let temp = tempfile::tempdir().expect("isolated directory");
    let (mut owner, _) =
        SnapshotStore::create_fresh(directory(&temp), b"prior synthetic checkpoint")
            .expect("fresh store");
    let transition = owner
        .begin_transition()
        .expect("reserve intent before accepting input");
    drop(transition);
    assert_eq!(owner.snapshot(), Err(StoreError::Poisoned));
    assert_eq!(
        owner.commit(b"prior synthetic checkpoint"),
        Err(StoreError::Poisoned)
    );
    drop(owner);
    assert_eq!(
        SnapshotStore::open_existing(directory(&temp)).err(),
        Some(StoreError::RecoveryRequired)
    );
}

#[test]
fn a_successful_transition_commits_the_candidate_and_clears_its_intent() {
    let temp = tempfile::tempdir().expect("isolated directory");
    let (mut owner, first) =
        SnapshotStore::create_fresh(directory(&temp), b"prior synthetic checkpoint")
            .expect("fresh store");
    let transition = owner
        .begin_transition()
        .expect("reserve before accepting candidate");
    let receipt = transition
        .commit(b"candidate synthetic checkpoint")
        .expect("commit candidate");
    assert!(receipt.changed());
    assert_eq!(receipt.generation(), first.generation() + 1);
    assert_eq!(receipt.durability(), first.durability());
    assert_eq!(
        owner.snapshot().expect("healthy committed owner"),
        b"candidate synthetic checkpoint"
    );
    drop(owner);
    let reopened = SnapshotStore::open_existing(directory(&temp)).expect("completed transition");
    assert_eq!(
        reopened.snapshot().expect("healthy"),
        b"candidate synthetic checkpoint"
    );
}

#[test]
fn an_explicit_same_byte_finish_clears_intent_without_incrementing_generation() {
    let temp = tempfile::tempdir().expect("isolated directory");
    let (mut owner, first) =
        SnapshotStore::create_fresh(directory(&temp), b"unchanged synthetic checkpoint")
            .expect("fresh store");
    let receipt = owner
        .begin_transition()
        .expect("reserve")
        .commit(b"unchanged synthetic checkpoint")
        .expect("explicit no-change finish");
    assert!(!receipt.changed());
    assert_eq!(receipt.generation(), first.generation());
    assert_eq!(receipt.durability(), first.durability());
    // A second transition is possible only after the first clears its own intent.
    let second = owner
        .begin_transition()
        .expect("clean next transition")
        .commit(b"unchanged synthetic checkpoint")
        .expect("finish next transition");
    assert_eq!(second, receipt);
    drop(owner);
    assert!(SnapshotStore::open_existing(directory(&temp)).is_ok());
}

#[test]
fn oversized_reserved_commit_is_not_an_implicit_abort_or_clean_retry() {
    let temp = tempfile::tempdir().expect("isolated directory");
    let (mut owner, _) =
        SnapshotStore::create_fresh(directory(&temp), b"prior synthetic checkpoint")
            .expect("fresh store");
    let oversized = vec![0xA5; MAX_SNAPSHOT_BYTES + 1];
    let transition = owner.begin_transition().expect("reserve");
    assert_eq!(
        transition.commit(&oversized),
        Err(StoreError::SnapshotTooLarge)
    );
    assert_eq!(owner.snapshot(), Err(StoreError::Poisoned));
    drop(owner);
    assert_eq!(
        SnapshotStore::open_existing(directory(&temp)).err(),
        Some(StoreError::RecoveryRequired)
    );
}

#[test]
fn foreign_staging_after_reservation_is_preserved_and_faults_the_transition() {
    let temp = tempfile::tempdir().expect("isolated directory");
    let (mut owner, _) =
        SnapshotStore::create_fresh(directory(&temp), b"prior synthetic checkpoint")
            .expect("fresh store");
    let transition = owner.begin_transition().expect("reserve");
    let path = temp.path().join(STAGING_FILE_NAME);
    fs::write(&path, b"foreign partial staging").expect("filesystem fault fixture");
    assert_eq!(
        transition.commit(b"candidate"),
        Err(StoreError::RecoveryRequired)
    );
    assert_eq!(owner.snapshot(), Err(StoreError::Poisoned));
    assert_eq!(
        fs::read(path).expect("foreign staging preserved"),
        b"foreign partial staging"
    );
    drop(owner);
    assert_eq!(
        SnapshotStore::open_existing(directory(&temp)).err(),
        Some(StoreError::RecoveryRequired)
    );
}

#[test]
fn same_byte_reserved_commit_rechecks_external_current_changes() {
    let temp = tempfile::tempdir().expect("isolated directory");
    let (mut owner, _) =
        SnapshotStore::create_fresh(directory(&temp), b"prior synthetic checkpoint")
            .expect("fresh store");
    let transition = owner.begin_transition().expect("reserve");
    let current = temp.path().join(SNAPSHOT_FILE_NAME);
    fs::write(&current, b"externally changed file").expect("filesystem fault fixture");
    assert_eq!(
        transition.commit(b"prior synthetic checkpoint"),
        Err(StoreError::ExternalChange)
    );
    assert_eq!(owner.snapshot(), Err(StoreError::Poisoned));
    assert_eq!(
        fs::read(current).expect("not overwritten"),
        b"externally changed file"
    );
    drop(owner);
    assert_eq!(
        SnapshotStore::open_existing(directory(&temp)).err(),
        Some(StoreError::RecoveryRequired)
    );
}

#[test]
fn a_failed_begin_is_unaccepted_input_and_does_not_clean_foreign_state() {
    let temp = tempfile::tempdir().expect("isolated directory");
    let (mut owner, _) =
        SnapshotStore::create_fresh(directory(&temp), b"prior synthetic checkpoint")
            .expect("fresh store");
    let staging = temp.path().join(STAGING_FILE_NAME);
    fs::write(&staging, b"preexisting foreign staging").expect("filesystem fault fixture");
    assert_eq!(
        owner.begin_transition().err(),
        Some(StoreError::RecoveryRequired)
    );
    assert_eq!(owner.snapshot(), Err(StoreError::Poisoned));
    assert!(
        !temp.path().join(INTENT_FILE_NAME).exists(),
        "no successful reservation occurred"
    );
    assert_eq!(
        fs::read(staging).expect("preserved"),
        b"preexisting foreign staging"
    );
    // This failed begin is never proof that a packet/drop was durably accepted.
}

#[test]
fn transition_debug_discloses_neither_checkpoint_nor_native_path() {
    let temp = tempfile::tempdir().expect("isolated directory");
    let (mut owner, _) =
        SnapshotStore::create_fresh(directory(&temp), b"SYNTHETIC_PRIVATE_CHECKPOINT")
            .expect("fresh store");
    let transition = owner.begin_transition().expect("reserve");
    let visible = format!("{transition:?}");
    assert!(!visible.contains("SYNTHETIC_PRIVATE_CHECKPOINT"));
    assert!(!visible.contains(&temp.path().to_string_lossy().to_string()));
    let receipt = transition
        .commit(b"SYNTHETIC_PRIVATE_CHECKPOINT")
        .expect("explicit finish");
    assert!(!receipt.changed());
}

#[cfg(windows)]
#[test]
fn a_blocked_rename_reports_uncertainty_and_preserves_the_intent() {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    let temp = tempfile::tempdir().expect("isolated directory");
    let (mut owner, _) =
        SnapshotStore::create_fresh(directory(&temp), b"prior synthetic checkpoint")
            .expect("fresh store");
    let transition = owner.begin_transition().expect("reserve");
    let blocker = OpenOptions::new()
        .read(true)
        .share_mode(0x0003)
        .open(temp.path().join(SNAPSHOT_FILE_NAME))
        .expect("deny share-delete for test rename");
    assert_eq!(
        transition.commit(b"candidate checkpoint"),
        Err(StoreError::CommitUncertain)
    );
    assert_eq!(owner.snapshot(), Err(StoreError::Poisoned));
    drop(blocker);
    drop(owner);
    assert_eq!(
        SnapshotStore::open_existing(directory(&temp)).err(),
        Some(StoreError::RecoveryRequired)
    );
}
