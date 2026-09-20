// SPDX-License-Identifier: GPL-2.0-or-later

use phone_state_store::{Durability, NativePrivateDirectory, SnapshotStore};

fn directory(temp: &tempfile::TempDir) -> NativePrivateDirectory {
    NativePrivateDirectory::from_native_app_data(temp.path()).expect("private test directory")
}

#[test]
fn a_committed_snapshot_reopens_with_explicit_platform_durability() {
    let temp = tempfile::tempdir().expect("isolated directory");
    let (mut store, initial) =
        SnapshotStore::create_fresh(directory(&temp), b"synthetic checkpoint one")
            .expect("fresh checkpoint");
    assert_eq!(initial.generation(), 1);
    assert!(initial.changed());
    assert_eq!(
        store.snapshot().expect("healthy"),
        b"synthetic checkpoint one"
    );

    let receipt = store.commit(b"synthetic checkpoint two").expect("commit");
    assert_eq!(receipt.generation(), 2);
    assert!(receipt.changed());
    #[cfg(windows)]
    assert_eq!(receipt.durability(), Durability::FileSyncedOnly);
    #[cfg(any(target_os = "android", target_os = "linux"))]
    assert_eq!(receipt.durability(), Durability::DirectorySynced);

    drop(store);
    let mut reopened = SnapshotStore::open_existing(directory(&temp)).expect("reopen");
    assert_eq!(
        reopened.snapshot().expect("healthy"),
        b"synthetic checkpoint two"
    );
    let unchanged = reopened
        .commit(b"synthetic checkpoint two")
        .expect("unchanged commit");
    assert_eq!(unchanged.generation(), 2);
    assert!(!unchanged.changed());
    assert_eq!(unchanged.durability(), receipt.durability());
}
