// SPDX-License-Identifier: GPL-2.0-or-later
// These are real isolated filesystem boundary tests with synthetic bytes.
// They do not establish Android device/power-loss or domain authorization proof.

use std::fs::{self, OpenOptions};

use phone_state_store::{
    INTENT_FILE_NAME, LOCK_FILE_NAME, MAX_SNAPSHOT_BYTES, NativePrivateDirectory,
    SNAPSHOT_FILE_NAME, STAGING_FILE_NAME, SnapshotStore, StoreError,
};
use sha2::{Digest, Sha256};

fn directory(temp: &tempfile::TempDir) -> NativePrivateDirectory {
    NativePrivateDirectory::from_native_app_data(temp.path()).expect("private test directory")
}

fn create(temp: &tempfile::TempDir, bytes: &[u8]) -> SnapshotStore {
    SnapshotStore::create_fresh(directory(temp), bytes)
        .expect("fresh synthetic store")
        .0
}

#[test]
fn opening_absent_state_does_not_initialize_or_default_it() {
    let temp = tempfile::tempdir().expect("isolated directory");
    assert_eq!(
        SnapshotStore::open_existing(directory(&temp)).err(),
        Some(StoreError::MissingState)
    );
    // The failed open did not create a lock or turn this into an incomplete store.
    let store = create(&temp, b"explicit native initial state");
    assert_eq!(
        store.snapshot().expect("healthy"),
        b"explicit native initial state"
    );
}

#[test]
fn fresh_creation_never_replaces_existing_state() {
    let temp = tempfile::tempdir().expect("isolated directory");
    drop(create(&temp, b"original synthetic checkpoint"));
    assert_eq!(
        SnapshotStore::create_fresh(directory(&temp), b"replacement").err(),
        Some(StoreError::StateAlreadyExists)
    );
    let reopened = SnapshotStore::open_existing(directory(&temp)).expect("original store");
    assert_eq!(
        reopened.snapshot().expect("healthy"),
        b"original synthetic checkpoint"
    );
}

#[test]
fn the_os_writer_lock_excludes_another_owner_until_drop() {
    let temp = tempfile::tempdir().expect("isolated directory");
    let owner = create(&temp, b"lock fixture");
    assert_eq!(
        SnapshotStore::open_existing(directory(&temp)).err(),
        Some(StoreError::WriterLocked)
    );
    drop(owner);
    assert!(SnapshotStore::open_existing(directory(&temp)).is_ok());
}

#[test]
fn missing_current_or_missing_lock_is_not_recreated() {
    for missing_name in [SNAPSHOT_FILE_NAME, LOCK_FILE_NAME] {
        let temp = tempfile::tempdir().expect("isolated directory");
        drop(create(&temp, b"synthetic checkpoint"));
        let missing = temp.path().join(missing_name);
        fs::remove_file(&missing).expect("simulate missing fixed artifact");
        assert_eq!(
            SnapshotStore::open_existing(directory(&temp)).err(),
            Some(StoreError::MissingState)
        );
        assert!(
            !missing.exists(),
            "failed open must not repair a missing file"
        );
        assert_eq!(
            SnapshotStore::create_fresh(directory(&temp), b"reset").err(),
            Some(StoreError::StateAlreadyExists)
        );
    }
}

#[test]
fn every_preexisting_partial_artifact_blocks_reopening_without_cleanup() {
    for name in [STAGING_FILE_NAME, INTENT_FILE_NAME] {
        for bytes in [
            b"".as_slice(),
            b"partial".as_slice(),
            b"WUACDIRT\x01".as_slice(),
        ] {
            let temp = tempfile::tempdir().expect("isolated directory");
            drop(create(&temp, b"previous synthetic checkpoint"));
            let path = temp.path().join(name);
            fs::write(&path, bytes).expect("simulate interrupted commit");
            assert_eq!(
                SnapshotStore::open_existing(directory(&temp)).err(),
                Some(StoreError::RecoveryRequired)
            );
            assert_eq!(fs::read(&path).expect("leftover preserved"), bytes);
            assert_eq!(
                SnapshotStore::create_fresh(directory(&temp), b"reset").err(),
                Some(StoreError::StateAlreadyExists)
            );
        }
    }
}

#[test]
fn a_failed_partial_commit_check_poisons_the_live_owner() {
    let temp = tempfile::tempdir().expect("isolated directory");
    let mut owner = create(&temp, b"previous synthetic checkpoint");
    let path = temp.path().join(INTENT_FILE_NAME);
    fs::write(&path, b"foreign partial intent").expect("simulate an external writer");
    assert_eq!(
        owner.commit(b"new checkpoint"),
        Err(StoreError::RecoveryRequired)
    );
    assert_eq!(owner.snapshot(), Err(StoreError::Poisoned));
    assert_eq!(
        owner.commit(b"previous synthetic checkpoint"),
        Err(StoreError::Poisoned)
    );
    assert_eq!(
        fs::read(path).expect("intent preserved"),
        b"foreign partial intent"
    );
}

#[test]
fn an_existing_empty_snapshot_is_corrupt_not_a_default() {
    let temp = tempfile::tempdir().expect("isolated directory");
    drop(create(&temp, b"synthetic checkpoint"));
    fs::write(temp.path().join(SNAPSHOT_FILE_NAME), []).expect("simulate truncated file");
    assert_eq!(
        SnapshotStore::open_existing(directory(&temp)).err(),
        Some(StoreError::CorruptSnapshot)
    );
}

#[test]
fn an_empty_domain_payload_is_preserved_not_reinterpreted() {
    let temp = tempfile::tempdir().expect("isolated directory");
    drop(create(&temp, b""));
    let owner = SnapshotStore::open_existing(directory(&temp)).expect("valid storage frame");
    assert_eq!(owner.snapshot().expect("opaque bytes"), b"");
    // A domain schema may reject this; the byte store must not invent defaults.
}

fn mutation_is_rejected(mutate: impl FnOnce(&mut Vec<u8>), expected: StoreError) {
    let temp = tempfile::tempdir().expect("isolated directory");
    drop(create(&temp, b"synthetic framing fixture"));
    let path = temp.path().join(SNAPSHOT_FILE_NAME);
    let mut frame = fs::read(&path).expect("published fixed-format fixture");
    mutate(&mut frame);
    fs::write(&path, &frame).expect("inject corruption at filesystem boundary");
    assert_eq!(
        SnapshotStore::open_existing(directory(&temp)).err(),
        Some(expected)
    );
    assert_eq!(fs::read(&path).expect("rejected frame preserved"), frame);
}

#[test]
fn fixed_frame_rejects_magic_version_generation_length_checksum_and_trailing_mutations() {
    mutation_is_rejected(|frame| frame[0] ^= 1, StoreError::CorruptSnapshot);
    mutation_is_rejected(
        |frame| frame[8..10].copy_from_slice(&2_u16.to_be_bytes()),
        StoreError::UnsupportedVersion,
    );
    mutation_is_rejected(|frame| frame[10..18].fill(0), StoreError::CorruptSnapshot);
    mutation_is_rejected(|frame| frame[17] ^= 2, StoreError::CorruptSnapshot);
    mutation_is_rejected(|frame| frame[21] ^= 1, StoreError::CorruptSnapshot);
    mutation_is_rejected(
        |frame| frame[18..22].copy_from_slice(&u32::MAX.to_be_bytes()),
        StoreError::SnapshotTooLarge,
    );
    mutation_is_rejected(|frame| frame[22] ^= 1, StoreError::CorruptSnapshot);
    mutation_is_rejected(|frame| frame[54] ^= 1, StoreError::CorruptSnapshot);
    mutation_is_rejected(
        |frame| {
            frame.pop();
        },
        StoreError::CorruptSnapshot,
    );
    mutation_is_rejected(|frame| frame.push(0), StoreError::CorruptSnapshot);
}

#[test]
fn exact_payload_cap_is_accepted_but_oversized_input_never_changes_prior_state() {
    let temp = tempfile::tempdir().expect("isolated directory");
    let oversized = vec![0xA5; MAX_SNAPSHOT_BYTES + 1];
    assert_eq!(
        SnapshotStore::create_fresh(directory(&temp), &oversized).err(),
        Some(StoreError::SnapshotTooLarge)
    );
    // Oversized fresh input has not left any store artifacts.
    let mut owner = create(&temp, b"small initial checkpoint");
    let exact = vec![0x5A; MAX_SNAPSHOT_BYTES];
    let receipt = owner.commit(&exact).expect("exact cap");
    assert_eq!(owner.commit(&oversized), Err(StoreError::SnapshotTooLarge));
    assert_eq!(
        owner.snapshot().expect("input rejection did not poison"),
        exact
    );
    assert_eq!(
        owner.commit(&exact).expect("unchanged").generation(),
        receipt.generation()
    );
    drop(owner);
    let reopened = SnapshotStore::open_existing(directory(&temp)).expect("bounded reopen");
    assert_eq!(reopened.snapshot().expect("healthy"), exact);
}

#[test]
fn an_oversized_on_disk_frame_is_rejected_without_reset() {
    let temp = tempfile::tempdir().expect("isolated directory");
    drop(create(&temp, b"synthetic checkpoint"));
    let path = temp.path().join(SNAPSHOT_FILE_NAME);
    let file = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("fault fixture");
    file.set_len((MAX_SNAPSHOT_BYTES + 55) as u64)
        .expect("one byte over fixed frame cap");
    drop(file);
    assert_eq!(
        SnapshotStore::open_existing(directory(&temp)).err(),
        Some(StoreError::SnapshotTooLarge)
    );
    assert_eq!(
        fs::metadata(path).expect("file preserved").len(),
        (MAX_SNAPSHOT_BYTES + 55) as u64
    );
}

#[test]
fn even_a_same_byte_commit_detects_a_valid_external_snapshot_and_poisons() {
    let temp = tempfile::tempdir().expect("isolated directory");
    let donor = tempfile::tempdir().expect("isolated donor");
    let mut owner = create(&temp, b"original synthetic checkpoint");
    drop(create(&donor, b"externally replaced synthetic checkpoint"));
    let external = fs::read(donor.path().join(SNAPSHOT_FILE_NAME)).expect("valid other frame");
    let path = temp.path().join(SNAPSHOT_FILE_NAME);
    fs::write(&path, &external).expect("simulate external replacement");
    assert_eq!(
        owner.commit(b"original synthetic checkpoint"),
        Err(StoreError::ExternalChange)
    );
    assert_eq!(owner.snapshot(), Err(StoreError::Poisoned));
    assert_eq!(fs::read(&path).expect("not overwritten"), external);
}

#[test]
fn generation_exhaustion_never_wraps_or_changes_the_frame() {
    let temp = tempfile::tempdir().expect("isolated directory");
    drop(create(&temp, b"synthetic last-generation fixture"));
    let path = temp.path().join(SNAPSHOT_FILE_NAME);
    let mut frame = fs::read(&path).expect("fixed storage frame");
    frame[10..18].copy_from_slice(&u64::MAX.to_be_bytes());
    let mut checksum = Sha256::new();
    checksum.update(&frame[..22]);
    checksum.update(&frame[54..]);
    frame[22..54].copy_from_slice(&checksum.finalize());
    fs::write(&path, &frame).expect("synthetic valid max-generation frame, not authentication");
    let mut owner = SnapshotStore::open_existing(directory(&temp)).expect("valid frame");
    assert_eq!(
        owner
            .commit(b"synthetic last-generation fixture")
            .expect("unchanged")
            .generation(),
        u64::MAX
    );
    assert_eq!(
        owner.commit(b"next checkpoint"),
        Err(StoreError::GenerationExhausted)
    );
    assert_eq!(owner.snapshot(), Err(StoreError::Poisoned));
    assert_eq!(fs::read(&path).expect("unmodified max frame"), frame);
}

#[test]
fn nonempty_lock_and_nonregular_fixed_entries_fail_closed() {
    let temp = tempfile::tempdir().expect("isolated directory");
    drop(create(&temp, b"synthetic checkpoint"));
    fs::write(temp.path().join(LOCK_FILE_NAME), b"not a zero-byte lock")
        .expect("corrupt lock fixture");
    assert_eq!(
        SnapshotStore::open_existing(directory(&temp)).err(),
        Some(StoreError::RecoveryRequired)
    );

    let other = tempfile::tempdir().expect("isolated directory");
    fs::create_dir(other.path().join(SNAPSHOT_FILE_NAME)).expect("directory where a file belongs");
    assert_eq!(
        SnapshotStore::create_fresh(directory(&other), b"reset").err(),
        Some(StoreError::UnsafeEntry)
    );
}

#[test]
fn directory_provenance_rejects_relative_parent_and_missing_paths() {
    assert_eq!(
        NativePrivateDirectory::from_native_app_data("relative-state").err(),
        Some(StoreError::UnsafeEntry)
    );
    let temp = tempfile::tempdir().expect("isolated directory");
    assert_eq!(
        NativePrivateDirectory::from_native_app_data(temp.path().join("..")).err(),
        Some(StoreError::UnsafeEntry)
    );
    let missing = temp.path().join("not-created");
    assert_eq!(
        NativePrivateDirectory::from_native_app_data(&missing).err(),
        Some(StoreError::DirectoryUnavailable)
    );
    assert!(!missing.exists());
}

#[test]
fn debug_and_errors_do_not_expose_paths_or_payloads() {
    let temp = tempfile::tempdir().expect("isolated directory");
    let dir = directory(&temp);
    let directory_debug = format!("{dir:?}");
    let (owner, _) = SnapshotStore::create_fresh(dir, b"SYNTHETIC_PAYLOAD_NOT_FOR_DEBUG")
        .expect("synthetic checkpoint");
    let visible = format!(
        "{directory_debug} {owner:?} {} {:?}",
        StoreError::CommitUncertain,
        StoreError::ReadFailed
    );
    assert!(!visible.contains("SYNTHETIC_PAYLOAD_NOT_FOR_DEBUG"));
    assert!(!visible.contains(&temp.path().to_string_lossy().to_string()));
}

#[cfg(windows)]
#[test]
fn windows_live_lock_and_ancestor_handles_reject_replacement() {
    let temp = tempfile::tempdir().expect("isolated directory");
    let state = temp.path().join("state");
    fs::create_dir(&state).expect("native test provisioning");
    let dir = NativePrivateDirectory::from_native_app_data(&state).expect("private child");
    let (mut owner, _) = SnapshotStore::create_fresh(dir, b"synthetic checkpoint").expect("create");
    assert!(fs::remove_file(state.join(LOCK_FILE_NAME)).is_err());
    assert!(fs::rename(&state, temp.path().join("relocated")).is_err());
    assert!(
        !owner
            .commit(b"synthetic checkpoint")
            .expect("lock still sound")
            .changed()
    );
}

#[cfg(unix)]
#[test]
fn unix_symlinks_and_hardlinks_are_not_followed() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().expect("isolated directory");
    let target = tempfile::tempdir().expect("isolated link target");
    drop(create(&target, b"target synthetic checkpoint"));
    let link = temp.path().join("alias");
    symlink(target.path(), &link).expect("test directory symlink");
    assert_eq!(
        NativePrivateDirectory::from_native_app_data(&link).err(),
        Some(StoreError::UnsafeEntry)
    );

    symlink(
        target.path().join(SNAPSHOT_FILE_NAME),
        temp.path().join(SNAPSHOT_FILE_NAME),
    )
    .expect("test file symlink");
    assert_eq!(
        SnapshotStore::create_fresh(directory(&temp), b"reset").err(),
        Some(StoreError::UnsafeEntry)
    );
    fs::remove_file(temp.path().join(SNAPSHOT_FILE_NAME)).expect("remove owned synthetic link");
    fs::hard_link(
        target.path().join(SNAPSHOT_FILE_NAME),
        temp.path().join(SNAPSHOT_FILE_NAME),
    )
    .expect("test hard link");
    assert_eq!(
        SnapshotStore::create_fresh(directory(&temp), b"reset").err(),
        Some(StoreError::UnsafeEntry)
    );
}

#[cfg(unix)]
#[test]
fn unix_external_lock_object_replacement_is_detected_before_commit() {
    let temp = tempfile::tempdir().expect("isolated directory");
    let mut owner = create(&temp, b"synthetic checkpoint");
    let lock = temp.path().join(LOCK_FILE_NAME);
    fs::remove_file(&lock).expect("simulate breach of private-parent invariant");
    fs::write(&lock, []).expect("substitute different lock inode");
    assert_eq!(
        owner.commit(b"synthetic checkpoint"),
        Err(StoreError::ExternalChange)
    );
    assert_eq!(owner.snapshot(), Err(StoreError::Poisoned));
}
